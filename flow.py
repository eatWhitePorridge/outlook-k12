"""精简版协议注册流程（仅「创建账号 + 拿 token」，无支付）。

8 步 happy path（platform OAuth client，不强制 add-phone）：
  1. GET  /api/accounts/authorize           种 login_session，推到 /create-account/password
  2. POST /api/accounts/user/register       提交 email + password [sentinel]
  3. GET  /api/accounts/email-otp/send      触发 OpenAI 发邮件
  4. (外部) otp_fetcher 拉 OTP（Cloud Mail）
  5. POST /api/accounts/email-otp/validate  验证 OTP [sentinel(authorize_continue)]
  6. POST /api/accounts/create_account      提交 name + birthdate [sentinel(oauth_create_account)]
  7. 重新 OAuth → chase ?code=               (含可选 workspace/select / organization/select)
  8. POST /oauth/token                      用 code + verifier 兑换 access/refresh/id_token

去掉了原项目里的：支付（PayPal/checkout）、add-phone、ChatGPT/Codex client 二次登录。
"""

from __future__ import annotations

import base64
import json
import logging
import random
import secrets
import string
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from .core.http_client import (
    AUTH_BASE,
    DEFAULT_SCOPE,
    PLATFORM_AUDIENCE,
    PLATFORM_AUTH0_CLIENT,
    PLATFORM_CLIENT_ID,
    PLATFORM_REDIRECT_URI,
    build_client,
    clear_oauth_session_cookies,
    json_headers,
    nav_headers,
    request_with_retry,
    set_oai_did_cookie,
)
from .core.pkce import new_device_id, new_pkce, random_state_nonce
from .core.profile import Profile, random_profile
from .core.sentinel import SentinelGenerator

logger = logging.getLogger(__name__)

# 异步 OTP 拉取器，签名 (email) -> str
OtpFetcher = Callable[[str], Awaitable[str]]


@dataclass(slots=True)
class RegisterResult:
    email: str
    password: str
    access_token: str
    refresh_token: str
    id_token: str
    device_id: str
    session_token: str = ""
    proxy_used: Optional[str] = None
    duration_seconds: float = 0.0
    # 从 token JWT claims 解出（供 sub2api 导出用）
    expires_in: int = 0
    chatgpt_account_id: str = ""
    chatgpt_user_id: str = ""
    plan_type: str = "plus"
    sub: str = ""
    auth_provider: str = ""
    token_source: str = "platform"
    workspace_id: str = ""
    workspace_joined: bool = False
    workspace_join_result: Optional[dict[str, Any]] = None
    platform_access_token: str = ""
    platform_refresh_token: str = ""
    platform_id_token: str = ""
    platform_expires_in: int = 0


class EmailOtpInvalidError(RuntimeError):
    """OpenAI 明确返回邮箱 OTP 错误/过期，可触发重新收码重试。"""


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _gen_password(length: int = 16) -> str:
    """随机强密码：>=8 位，至少 1 个大写/小写/数字。"""
    alphabet = string.ascii_letters + string.digits
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p):
            return p


def _gen_birthday() -> str:
    """随机生日 yyyy-mm-dd（年龄 25-45）。"""
    year = datetime.utcnow().year - random.randint(25, 45)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def _pick_code_from_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    qs = parse_qs(urlparse(raw_url).query)
    arr = qs.get("code") or []
    return arr[0] if arr else ""


def _snippet(s: str, max_len: int = 240) -> str:
    return s if len(s) <= max_len else s[:max_len] + "…"


def _jwt_claims(token: str) -> dict[str, Any]:
    """解码 JWT payload（不验签，只取 claims）。"""
    if not token:
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    pad = "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# 各 endpoint 调用
# ---------------------------------------------------------------------------


async def _platform_authorize(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    pkce_challenge: str,
    state_val: str,
    nonce_val: str,
    email: str,
) -> None:
    """Step 1: 起 OAuth flow，种 login_session，推到 /create-account/password。"""
    params = {
        "issuer": AUTH_BASE,
        "client_id": PLATFORM_CLIENT_ID,
        "audience": PLATFORM_AUDIENCE,
        "redirect_uri": PLATFORM_REDIRECT_URI,
        "device_id": device_id,
        "screen_hint": "login_or_signup",
        "max_age": "0",
        "login_hint": email,
        "scope": DEFAULT_SCOPE,
        "response_type": "code",
        "response_mode": "query",
        "state": state_val,
        "nonce": nonce_val,
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
        "auth0Client": PLATFORM_AUTH0_CLIENT,
    }
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = "https://platform.openai.com/"
    resp = await request_with_retry(
        client, "GET", f"{AUTH_BASE}/api/accounts/authorize",
        params=params, headers=headers,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"authorize HTTP {resp.status_code}: {_snippet(resp.text)}")


async def _user_register(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    password: str,
) -> bool:
    """Step 2: 提交 email + password（sentinel flow=username_password_create）。"""
    tok = await sentinel.sentinel_token(client, "username_password_create")
    body = json.dumps({"username": email, "password": password})
    headers = json_headers(profile, device_id, f"{AUTH_BASE}/create-account/password")
    headers["openai-sentinel-token"] = tok
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/user/register",
        content=body, headers=headers,
    )
    if resp.status_code in (200, 201):
        return True
    raw = resp.text or ""
    if '"invalid_auth_step"' in raw:
        # 上次注册流程已走到 email_otp 阶段；续跑 send/validate，不要直接失败。
        return False
    if "Failed to create account" in raw:
        raise RuntimeError(f"HTTP {resp.status_code}（邮箱域可能被标记滥用）: {_snippet(raw)}")
    raise RuntimeError(f"user/register HTTP {resp.status_code}: {_snippet(raw)}")


async def _send_email_otp(
    client: httpx.AsyncClient, *, profile: Profile, device_id: str,
) -> None:
    """Step 3: 触发邮件（GET + navigate 头，cors 会被 sentinel 砍）。"""
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = f"{AUTH_BASE}/create-account/password"
    resp = await request_with_retry(
        client, "GET", f"{AUTH_BASE}/api/accounts/email-otp/send", headers=headers,
    )
    if resp.status_code not in (200, 302):
        raise RuntimeError(f"email-otp/send HTTP {resp.status_code}: {_snippet(resp.text)}")


async def _validate_email_otp(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    otp: str,
) -> str:
    """Step 5: 验证 OTP。先不带 sentinel 试一次，失败再带 sentinel 重试。"""
    body = json.dumps({"code": otp})
    headers = json_headers(profile, device_id, f"{AUTH_BASE}/email-verification")
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/email-otp/validate",
        content=body, headers=headers,
    )
    if resp.status_code == 200:
        try:
            out = resp.json() if resp.text else {}
        except Exception:  # noqa: BLE001
            out = {}
        if isinstance(out, dict):
            return str(
                out.get("continue_url")
                or out.get("redirect_uri")
                or out.get("redirect_url")
                or out.get("url")
                or ""
            )
        return ""
    tok = await sentinel.sentinel_token(client, "authorize_continue")
    headers["openai-sentinel-token"] = tok
    resp2 = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/email-otp/validate",
        content=body, headers=headers,
    )
    if resp2.status_code != 200:
        raw = resp2.text or ""
        low = raw.lower()
        if (
            "wrong_email_otp_code" in low
            or "wrong code" in low
            or "incorrect" in low
            or "expired" in low
        ):
            raise EmailOtpInvalidError(
                f"email-otp/validate HTTP {resp2.status_code}: {_snippet(raw)}"
            )
        raise RuntimeError(f"email-otp/validate HTTP {resp2.status_code}: {_snippet(raw)}")
    try:
        out = resp2.json() if resp2.text else {}
    except Exception:  # noqa: BLE001
        out = {}
    if isinstance(out, dict):
        return str(
            out.get("continue_url")
            or out.get("redirect_uri")
            or out.get("redirect_url")
            or out.get("url")
            or ""
        )
    return ""


async def _fetch_and_validate_email_otp(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    otp_fetcher: OtpFetcher,
    log: Callable[[str], None],
    max_attempts: int = 3,
    last_code: str = "",
) -> str:
    """拉取并验证邮箱 OTP；验证码错误时重新触发发码并重试。"""
    otp = last_code
    for attempt in range(1, max_attempts + 1):
        if not otp:
            log(f"📬 [5/8] 等邮箱收码（尝试 {attempt}/{max_attempts}）...")
            otp = await otp_fetcher(email)
            log(f"📨 [5/8] 收到验证码 {otp[:2]}**{otp[-2:]}")
        log(f"🔑 [6/8] 回填验证码（尝试 {attempt}/{max_attempts}）...")
        try:
            await _validate_email_otp(
                client, sentinel, profile=profile, device_id=device_id, otp=otp,
            )
            return otp
        except EmailOtpInvalidError as exc:
            if attempt >= max_attempts:
                raise
            log(f"🔁 [6/8] OTP 被拒，重新触发邮件验证码后重试：{exc}")
            otp = ""
            await _send_email_otp(client, profile=profile, device_id=device_id)
    raise RuntimeError("email OTP 重试耗尽")


async def _create_account(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    full_name: str,
    birthday: str,
) -> None:
    """Step 6: 提交 name + birthdate（sentinel flow=oauth_create_account）。"""
    tok = await sentinel.sentinel_token(client, "oauth_create_account")
    body = json.dumps({"name": full_name, "birthdate": birthday})
    headers = json_headers(profile, device_id, f"{AUTH_BASE}/about-you")
    headers["openai-sentinel-token"] = tok
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/create_account",
        content=body, headers=headers,
    )
    if resp.status_code in (200, 302):
        return
    raw = resp.text or ""
    if resp.status_code == 400 and "user_already_exists" in raw:
        # 2026-07 实测部分邮箱在 email-otp/validate 后账号已落库，
        # create_account 再提交会返回 user_already_exists；后续重新 authorize 仍可拿 code。
        return
    raise RuntimeError(f"create_account HTTP {resp.status_code}: {_snippet(raw)}")


# ---------------------------------------------------------------------------
# Phase 2: 重新走一遍 OAuth login 拿 ?code=
# ---------------------------------------------------------------------------


async def _prime_authorize(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    pkce_challenge: str,
    state_val: str,
    nonce_val: str,
    email: str,
) -> str:
    """重新 GET /api/accounts/authorize 并手动 chase（最多 10 跳）找 ?code=。

    注册阶段种下"已登录"cookie 后，OpenAI 看到时会直接 307 到 redirect_uri?code=，
    半路截获；没拿到返回空串，调用方走 password/verify。
    """
    params = {
        "issuer": AUTH_BASE,
        "client_id": PLATFORM_CLIENT_ID,
        "audience": PLATFORM_AUDIENCE,
        "redirect_uri": PLATFORM_REDIRECT_URI,
        "device_id": device_id,
        "screen_hint": "login_or_signup",
        "max_age": "0",
        "login_hint": email,
        "scope": DEFAULT_SCOPE,
        "response_type": "code",
        "response_mode": "query",
        "state": state_val,
        "nonce": nonce_val,
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
        "auth0Client": PLATFORM_AUTH0_CLIENT,
    }
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = "https://platform.openai.com/"

    cur_url = f"{AUTH_BASE}/api/accounts/authorize"
    cur_params: Optional[dict[str, str]] = params
    for hop in range(10):
        resp = await request_with_retry(
            client, "GET", cur_url, params=cur_params, headers=headers,
            follow_redirects=False,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"prime authorize HTTP {resp.status_code} (hop {hop}): {_snippet(resp.text)}"
            )
        loc = resp.headers.get("Location", "")
        if loc:
            full = loc if loc.startswith("http") else urljoin(str(resp.url), loc)
            code = _pick_code_from_url(full)
            if code:
                return code
            cur_url = full
            cur_params = None
            continue
        return ""
    return ""


async def _password_verify(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    password: str,
) -> tuple[bool, str]:
    """POST /api/accounts/password/verify。

    Returns:
        (needs_email_otp, continue_url)。撞 add_phone / phone_otp 墙时直接抛错
        （精简版不接 SMS）。
    """
    tok = await sentinel.sentinel_token(client, "password_verify")
    body = json.dumps({"password": password})
    headers = json_headers(profile, device_id, f"{AUTH_BASE}/log-in/password")
    headers["openai-sentinel-token"] = tok
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/password/verify",
        content=body, headers=headers,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"password/verify HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        out = resp.json()
    except Exception:  # noqa: BLE001
        out = {}
    page_type = ((out.get("page") or {}).get("type") or "").strip()
    cont = (out.get("continue_url") or "").strip()
    if page_type == "add_phone":
        raise RuntimeError("password/verify 撞 add_phone 墙（精简版未实现添加手机号）")
    if page_type in ("phone_verification", "phone_otp"):
        raise RuntimeError("password/verify 撞短信验证（精简版不接 SMS）")
    if page_type in ("email_otp_verification", "otp_verification"):
        return True, cont
    if not cont:
        raise RuntimeError(
            f"password/verify 没 continue_url，page.type={page_type}, body={_snippet(resp.text)}"
        )
    return False, cont


# ---------------------------------------------------------------------------
# Consent / code 抓取
# ---------------------------------------------------------------------------


async def _chase_to_code(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    start_url: str,
    max_hops: int = 10,
) -> str:
    """GET start_url，最多 hop max_hops 次找 ?code=。"""
    cur = start_url
    for _ in range(max_hops):
        headers = nav_headers(profile, device_id, site="same-origin")
        headers["Referer"] = AUTH_BASE + "/"
        resp = await request_with_retry(
            client, "GET", cur, headers=headers, follow_redirects=False
        )
        loc = resp.headers.get("Location", "")
        if loc:
            full = loc if loc.startswith("http") else urljoin(cur, loc)
            code = _pick_code_from_url(full)
            if code:
                return code
            cur = full
            continue
        code = _pick_code_from_url(str(resp.url))
        if code:
            return code
        return ""
    return ""


def _pick_workspace_id_from_cookie(client: httpx.AsyncClient) -> str:
    """从 oai-client-auth-session cookie 解码取 workspaces[0].id。"""
    for cookie in client.cookies.jar:
        if cookie.name != "oai-client-auth-session":
            continue
        raw = cookie.value or ""
        parts = raw.split(".")
        if not parts:
            continue
        head = parts[0]
        pad = "=" * (-len(head) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(head + pad).decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        ws = payload.get("workspaces") or []
        if ws and isinstance(ws[0], dict) and ws[0].get("id"):
            return str(ws[0]["id"])
    return ""


async def _extract_code(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    continue_url: str,
) -> str:
    """Step 7: 完整 consent 链路找 ?code=（chase → workspace/select → organization/select）。"""
    code = await _chase_to_code(
        client, profile=profile, device_id=device_id, start_url=continue_url
    )
    if code:
        return code

    ws_id = _pick_workspace_id_from_cookie(client)
    if not ws_id:
        raise RuntimeError(
            "consent chase 没拿到 ?code= 且 cookie 里没 workspaces[]，注册可能没成功"
        )
    ws_body = json.dumps({"workspace_id": ws_id})
    ws_headers = json_headers(profile, device_id, continue_url)
    ws_resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/workspace/select",
        content=ws_body, headers=ws_headers, follow_redirects=False,
    )
    code = _pick_code_from_url((ws_resp.headers.get("Location") or "").strip())
    if code:
        return code
    try:
        ws_out = ws_resp.json()
    except Exception:  # noqa: BLE001
        ws_out = {}
    ws_continue = (ws_out.get("continue_url") or "").strip()
    if ws_continue:
        code = await _chase_to_code(
            client, profile=profile, device_id=device_id, start_url=ws_continue
        )
        if code:
            return code

    orgs = (ws_out.get("data") or {}).get("orgs") or []
    if not orgs:
        raise RuntimeError(f"workspace/select 后没 ?code= 也没 orgs[]，body={_snippet(ws_resp.text)}")
    org_id = (orgs[0].get("id") or "").strip()
    if not org_id:
        raise RuntimeError("workspace/select 返回的 orgs[0].id 为空")
    projects = orgs[0].get("projects") or []
    proj_id = (projects[0].get("id") or "").strip() if projects else ""

    org_body_dict: dict[str, Any] = {"org_id": org_id}
    if proj_id:
        org_body_dict["project_id"] = proj_id
    org_headers = json_headers(profile, device_id, continue_url)
    if ws_continue:
        org_headers["referer"] = ws_continue
    org_resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/organization/select",
        content=json.dumps(org_body_dict), headers=org_headers, follow_redirects=False,
    )
    code = _pick_code_from_url((org_resp.headers.get("Location") or "").strip())
    if code:
        return code
    try:
        org_out = org_resp.json()
    except Exception:  # noqa: BLE001
        org_out = {}
    org_continue = (org_out.get("continue_url") or "").strip()
    if org_continue:
        code = await _chase_to_code(
            client, profile=profile, device_id=device_id, start_url=org_continue
        )
        if code:
            return code
    raise RuntimeError(
        f"organization/select 也没 ?code=, status={org_resp.status_code}, body={_snippet(org_resp.text)}"
    )


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


async def _token_exchange(
    client: httpx.AsyncClient, *, code: str, pkce_verifier: str,
) -> tuple[str, str, str, int]:
    """Step 8: 用 code + verifier 换 (access_token, refresh_token, id_token, expires_in)。"""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": PLATFORM_REDIRECT_URI,
        "client_id": PLATFORM_CLIENT_ID,
        "code_verifier": pkce_verifier,
    }
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/oauth/token",
        content=urlencode(form),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    if resp.status_code != 200:
        raise RuntimeError(f"/oauth/token HTTP {resp.status_code}: {_snippet(resp.text)}")
    data = resp.json()
    access = data.get("access_token") or ""
    refresh = data.get("refresh_token") or ""
    id_token = data.get("id_token") or ""
    expires_in = int(data.get("expires_in") or 0)
    if not access:
        raise RuntimeError(f"/oauth/token 缺 access_token: {_snippet(resp.text)}")
    return access, refresh, id_token, expires_in


# ---------------------------------------------------------------------------
# 顶层 API
# ---------------------------------------------------------------------------


async def register_via_protocol(
    *,
    email: str,
    proxy: Optional[str],
    otp_fetcher: OtpFetcher,
    password: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    birthday: Optional[str] = None,
    fetch_account_id: bool = True,
    log: Optional[Callable[[str], None]] = None,
    profile: Optional[Profile] = None,
    post_token_hook: Optional[
        Callable[[httpx.AsyncClient, Profile, str, RegisterResult], Awaitable[None]]
    ] = None,
) -> RegisterResult:
    """精简版协议注册（创建账号 + 拿 token，无支付）。

    Args:
        email: 已能收信的邮箱（Cloud Mail 子邮箱）
        proxy: 代理 URL（http://user:pass@host:port），None=直连
        otp_fetcher: 异步函数 `async def(email) -> str`，返回 6 位 OTP
        password: 留空 → 自动生成 16 位强密码
        first_name / last_name / birthday: 留空 → 随机
        log: 进度日志回调；默认 logger.info
        profile: 浏览器指纹；留空 → 随机
    """
    import time as _t

    started = _t.monotonic()
    p = profile or random_profile()
    info = log or (lambda s: logger.info(s))

    if not password:
        password = _gen_password(16)
    fn = first_name or "".join(secrets.choice(string.ascii_lowercase) for _ in range(7)).capitalize()
    ln = last_name or "".join(secrets.choice(string.ascii_lowercase) for _ in range(8)).capitalize()
    full_name = f"{fn} {ln}".strip()
    bd = birthday or _gen_birthday()

    device_id = new_device_id()
    pkce = new_pkce()
    state_val, nonce_val = random_state_nonce()
    result_obj: Optional[RegisterResult] = None

    info(f"🎒 [1/8] 准备身份卡 · UA={p.user_agent[:32]}... locale={p.locale}")

    async with build_client(profile=p, proxy=proxy) as client:
        set_oai_did_cookie(client, device_id)
        sentinel = SentinelGenerator(device_id=device_id, user_agent=p.user_agent)

        info("👋 [2/8] 敲门 authorize ...")
        await _platform_authorize(
            client, profile=p, device_id=device_id,
            pkce_challenge=pkce.challenge, state_val=state_val,
            nonce_val=nonce_val, email=email,
        )

        info("📝 [3/8] 提交账号密码 ...")
        fresh_register = await _user_register(
            client, sentinel, profile=p, device_id=device_id,
            email=email, password=password,
        )
        if not fresh_register:
            info("🔁 [3/8] 检测到邮箱已在 email_otp 阶段，续跑验证码步骤 ...")

        info("📮 [4/8] 触发邮箱验证码 ...")
        await _send_email_otp(client, profile=p, device_id=device_id)

        otp = await _fetch_and_validate_email_otp(
            client, sentinel, profile=p, device_id=device_id,
            email=email, otp_fetcher=otp_fetcher, log=info,
        )

        info(f"🎂 [7/8] 录入资料 · 生日 {bd}，建账号 ...")
        await _create_account(
            client, sentinel, profile=p, device_id=device_id,
            full_name=full_name, birthday=bd,
        )

        # Phase 2：清旧 session，用新 PKCE 重新 authorize 拿 ?code=
        info("🧹 [8/8] 清理旧会话，重新 PKCE ...")
        clear_oauth_session_cookies(client)
        pkce2 = new_pkce()
        state2, nonce2 = random_state_nonce()

        info("🔁 [8/8] 追跳转链找授权 code ...")
        code = await _prime_authorize(
            client, profile=p, device_id=device_id,
            pkce_challenge=pkce2.challenge, state_val=state2,
            nonce_val=nonce2, email=email,
        )
        if code:
            info("🎯 [8/8] 直接拿到 code")
        else:
            info("🔐 [8/8] 走密码登录路径 ...")
            needs_otp, continue_url = await _password_verify(
                client, sentinel, profile=p, device_id=device_id, password=password,
            )
            if needs_otp:
                info(f"📨 [8/8] 撞二次验证，复用 OTP {otp[:2]}**{otp[-2:]} ...")
                try:
                    await _validate_email_otp(
                        client, sentinel, profile=p, device_id=device_id, otp=otp,
                    )
                except RuntimeError as exc:
                    msg = str(exc).lower()
                    if (
                        isinstance(exc, EmailOtpInvalidError)
                        or "incorrect" in msg
                        or "expired" in msg
                        or "wrong_email_otp_code" in msg
                        or "wrong code" in msg
                    ):
                        info("🔁 [8/8] OTP 被拒，再拉一条新的 ...")
                        otp2 = await otp_fetcher(email)
                        await _validate_email_otp(
                            client, sentinel, profile=p, device_id=device_id, otp=otp2,
                        )
                    else:
                        raise
            if not continue_url:
                continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"
            info("✅ [8/8] 追 consent 拿 code ...")
            code = await _extract_code(
                client, profile=p, device_id=device_id, continue_url=continue_url
            )
            info("🎯 [8/8] 拿到 code")

        info("🎁 [8/8] 兑换 access / refresh / id_token ...")
        access, refresh, id_tok, expires_in = await _token_exchange(
            client, code=code, pkce_verifier=pkce2.verifier,
        )
        info(
            f"🪙 [8/8] token 拿齐：access(len={len(access)}) "
            f"refresh(len={len(refresh)}) id_token(len={len(id_tok)})"
        )

        # 解 platform token claims（默认值）
        access_claims = _jwt_claims(access)
        id_claims = _jwt_claims(id_tok)
        auth_info = access_claims.get("https://api.openai.com/auth") or {}
        chatgpt_account_id = str(auth_info.get("chatgpt_account_id") or "")
        chatgpt_user_id = str(auth_info.get("chatgpt_user_id") or "")
        plan_type = str(auth_info.get("chatgpt_plan_type") or "plus")
        sub = str(id_claims.get("sub") or access_claims.get("sub") or "")

        # 复用「仍登录着」的同一 session，用 Codex client 再 authorize 拿 chatgpt_account_id。
        # 不走密码登录（密码登录会撞 add_phone）；team 账号此时自动进 team，授权链路走通。
        if fetch_account_id and not chatgpt_account_id:
            info("🪪 [+] 复用登录态，走 Codex client 拿 chatgpt_account_id ...")
            try:
                from .chatgpt_login import fetch_account_id_via_session

                acc = await fetch_account_id_via_session(
                    client, profile=p, device_id=device_id, email=email,
                )
                # 用 Codex token 覆盖（带 account_id）
                access = acc.access_token or access
                refresh = acc.refresh_token or refresh
                id_tok = acc.id_token or id_tok
                expires_in = acc.expires_in or expires_in
                chatgpt_account_id = acc.chatgpt_account_id or chatgpt_account_id
                chatgpt_user_id = acc.chatgpt_user_id or chatgpt_user_id
                plan_type = acc.plan_type or plan_type
                sub = acc.sub or sub
                info(f"🪪 [+] 拿到 chatgpt_account_id = {chatgpt_account_id or '(仍为空)'}")
            except Exception as exc:  # noqa: BLE001
                info(f"⚠️ [+] Codex 授权失败，保留 platform token（account_id 留空）：{exc}")

        elapsed = _t.monotonic() - started
        result_obj = RegisterResult(
            email=email,
            password=password,
            access_token=access,
            refresh_token=refresh,
            id_token=id_tok,
            device_id=device_id,
            proxy_used=proxy,
            duration_seconds=elapsed,
            expires_in=expires_in,
            chatgpt_account_id=chatgpt_account_id,
            chatgpt_user_id=chatgpt_user_id,
            plan_type=plan_type,
            sub=sub,
        )
        if post_token_hook is not None:
            await post_token_hook(client, p, device_id, result_obj)

    if result_obj is None:
        raise RuntimeError("register_via_protocol 内部状态异常：缺少结果对象")
    return result_obj


__all__ = ["RegisterResult", "OtpFetcher", "register_via_protocol"]
