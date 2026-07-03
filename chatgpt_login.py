"""ChatGPT CLI client PKCE OAuth login（HTTP-only，替代浏览器 oauth_login）。

目标：把 workers/oauth_login.py 在 Playwright 里跑的全流程改成纯 HTTP，
~13 秒拿到 access_token / refresh_token / id_token，无浏览器、无 Cloak、无指纹。

client 配置跟 workers/oauth_login.py 完全一致：
  - CLIENT_ID    = app_EMoamEEZ73f0CkXaXp7hrann   (ChatGPT CLI / Codex)
  - REDIRECT_URI = http://localhost:1455/auth/callback
  - SCOPE        = openid profile email offline_access

流程（跟 protocol_register.flow 的注册流程同构，只是 client 不同）：
  Step 1: PKCE / device_id / state / nonce
  Step 2: GET /api/accounts/authorize?client_id=app_EMoamEE...&redirect_uri=localhost:1455...
          - 手动 chase（follow_redirects=False），半路 Location 含 ?code= 就直接拿到
          - 没拿到则落到 /log-in/password
  Step 3: POST /api/accounts/password/verify（密码登录；OPT email_otp 二次验证）
  Step 4: chase continue_url -> /sign-in-with-chatgpt/codex/consent
  Step 5: POST /api/accounts/workspace/select  body={workspace_id}（从 cookie 解码）
                                                -> 返回 orgs + continue_url
  Step 6: POST /api/accounts/organization/select body={org_id, project_id}
                                                -> 返回 localhost:1455/auth/callback?code=
  Step 7: POST /oauth/token 用 code + verifier 兑换 token

如果撞 email_otp 二次验证，调用方需要传 otp_fetcher 回调（异步 (email) -> str）；
如果不传则抛 EmailOtpRequiredError，由上层决定怎么处理（浏览器 fallback / 不支持等）。
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

from .flow import _password_verify, _validate_email_otp
from .core.http_client import (
    AUTH_BASE,
    build_client,
    json_headers,
    nav_headers,
    request_with_retry,
)
from .core.pkce import new_device_id, new_pkce, random_state_nonce
from .core.profile import Profile, random_profile
from .core.sentinel import SentinelGenerator

CHATGPT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CHATGPT_REDIRECT_URI = "http://localhost:1455/auth/callback"
CHATGPT_SCOPE = "openid profile email offline_access"

OtpFetcher = Callable[[str], Awaitable[str]]


class EmailOtpRequiredError(RuntimeError):
    """password/verify 后撞到 email_otp 二次验证，但调用方没提供 OTP 拉取器。"""


@dataclass(slots=True)
class ChatGPTLoginResult:
    """协议登录的最终成果，字段与浏览器 oauth_login.py emit_success 完全对齐。"""

    email: str
    access_token: str
    id_token: str
    refresh_token: str
    expires_in: int
    chatgpt_account_id: str
    chatgpt_user_id: str
    plan_type: str
    sub: str
    duration_seconds: float = 0.0
    device_id: str = ""
    proxy_used: Optional[str] = None

    def to_emit_payload(self, *, fingerprint_seed: int = 0) -> dict[str, Any]:
        """转换成跟浏览器 worker emit_success(**payload) 完全一致的 camelCase dict。"""
        return {
            "email": self.email,
            "accessToken": self.access_token,
            "idToken": self.id_token,
            "refreshToken": self.refresh_token,
            "expiresIn": self.expires_in,
            "chatgptAccountId": self.chatgpt_account_id,
            "chatgptUserId": self.chatgpt_user_id,
            "planType": self.plan_type,
            "sub": self.sub,
            "fingerprintSeed": fingerprint_seed,
        }


# -----------------------------------------------------------------------------
# 内部工具
# -----------------------------------------------------------------------------


def _jwt_claims(token: str) -> dict[str, Any]:
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


def _pick_code_from_url(url: str) -> str:
    """从 Location/URL 里抓 ?code=...&state=... 的 code。"""
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        return (qs.get("code", [""])[0] or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _decode_client_auth_cookie(cookie_val: str) -> dict[str, Any]:
    parts = cookie_val.split(".")
    if not parts:
        return {}
    b64 = parts[0]
    pad = "=" * (-len(b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return payload if isinstance(payload, dict) else {}


def _iter_client_auth_payloads_from_cookies(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for cookie in client.cookies.jar:
        if cookie.name == "oai-client-auth-session":
            payload = _decode_client_auth_cookie(cookie.value or "")
            if payload:
                payloads.append(payload)
    payloads.sort(
        key=lambda p: (
            p.get("openai_client_id") != CHATGPT_CLIENT_ID,
            p.get("destination_app_name") != "Codex",
            p.get("app_name_enum") != "oaicli",
        )
    )
    return payloads


def _extract_workspace_id_from_session_cookie(client: httpx.AsyncClient) -> str:
    """从 Codex 的 oai-client-auth-session cookie 解码 workspaces[0].id。"""
    for payload in _iter_client_auth_payloads_from_cookies(client):
        workspaces = payload.get("workspaces") or []
        if isinstance(workspaces, list) and workspaces:
            first = workspaces[0]
            if isinstance(first, dict):
                ws_id = str(first.get("id") or "")
                if ws_id:
                    return ws_id
    return ""


def _extract_client_auth_payload_from_cookie(client: httpx.AsyncClient) -> dict[str, Any]:
    payloads = _iter_client_auth_payloads_from_cookies(client)
    return payloads[0] if payloads else {}


def _extract_orgs_from_client_auth_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[Any] = [payload]
    for key in ("client_auth_session", "data"):
        val = payload.get(key)
        if isinstance(val, dict):
            candidates.append(val)
    for src in candidates:
        if not isinstance(src, dict):
            continue
        raw_orgs = src.get("orgs") or src.get("organizations")
        if isinstance(raw_orgs, list):
            orgs = [o for o in raw_orgs if isinstance(o, dict)]
            if orgs:
                return orgs
        raw_workspaces = src.get("workspaces")
        if isinstance(raw_workspaces, list):
            orgs = [w for w in raw_workspaces if isinstance(w, dict)]
            if orgs:
                return orgs
    return []


async def _client_auth_session_dump(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    referer: str,
) -> dict[str, Any]:
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = referer
    headers["Accept"] = "application/json, text/plain, */*"
    resp = await request_with_retry(
        client,
        "GET",
        f"{AUTH_BASE}/api/accounts/client_auth_session_dump",
        headers=headers,
        follow_redirects=False,
        retries=2,
    )
    if resp.status_code != 200:
        return {}
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return {}
    return body if isinstance(body, dict) else {}


# -----------------------------------------------------------------------------
# Step 2: GET /api/accounts/authorize -- 半路截获 localhost:1455?code=
# -----------------------------------------------------------------------------


async def chatgpt_authorize(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    pkce_challenge: str,
    state_val: str,
    nonce_val: str,
    email: str,
) -> tuple[str, str]:
    """开新 ChatGPT OAuth login flow。

    Returns:
        (code, last_location)。code 非空 = 半路就拿到了（极少见）；
        空 = 需要走密码登录。last_location 用于判断停在哪个页面。
    """
    params = {
        "issuer": AUTH_BASE,
        "client_id": CHATGPT_CLIENT_ID,
        "audience": "https://api.openai.com/v1",
        "redirect_uri": CHATGPT_REDIRECT_URI,
        "device_id": device_id,
        "prompt": "login",
        "screen_hint": "login",
        "max_age": "0",
        "login_hint": email,
        "scope": CHATGPT_SCOPE,
        "response_type": "code",
        "response_mode": "query",
        "state": state_val,
        "nonce": nonce_val,
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
    }
    headers = nav_headers(profile, device_id, site="cross-site")
    headers["Referer"] = "https://chatgpt.com/"

    cur_url = f"{AUTH_BASE}/api/accounts/authorize"
    cur_params: dict[str, str] | None = params
    last_location = ""
    for _hop in range(12):
        resp = await request_with_retry(
            client, "GET", cur_url, params=cur_params, headers=headers,
            follow_redirects=False, retries=2,
        )
        loc = (resp.headers.get("Location") or "").strip()
        if resp.status_code in (301, 302, 303, 307, 308) and loc:
            if loc.startswith(CHATGPT_REDIRECT_URI) or (
                "localhost:1455" in loc and "/auth/callback" in loc
            ):
                code = _pick_code_from_url(loc)
                return code, loc
            cur_url = AUTH_BASE + loc if loc.startswith("/") else loc
            cur_params = None
            last_location = cur_url
            continue
        last_location = str(resp.url)
        code = _pick_code_from_url(last_location)
        return code, last_location
    return "", last_location


# -----------------------------------------------------------------------------
# chase Location 链 -> 找 localhost:1455/auth/callback?code=
# -----------------------------------------------------------------------------


async def chase_to_localhost_code(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    start_url: str,
    max_hops: int = 12,
) -> tuple[str, str]:
    """跟随 continue_url 链直到 Location 指向 localhost:1455/auth/callback?code="""
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = f"{AUTH_BASE}/"

    cur_url = start_url
    last_location = ""
    for _hop in range(max_hops):
        resp = await request_with_retry(
            client, "GET", cur_url, headers=headers,
            follow_redirects=False, retries=2,
        )
        loc = (resp.headers.get("Location") or "").strip()
        if resp.status_code in (301, 302, 303, 307, 308) and loc:
            if loc.startswith(CHATGPT_REDIRECT_URI) or (
                "localhost:1455" in loc and "/auth/callback" in loc
            ):
                return _pick_code_from_url(loc), loc
            cur_url = AUTH_BASE + loc if loc.startswith("/") else loc
            last_location = cur_url
            continue
        return _pick_code_from_url(str(resp.url)), str(resp.url)
    return "", last_location


def _extract_login_verifier_from_cookie(client: httpx.AsyncClient) -> str:
    """从 login_session cookie 解出 login_challenge（A 版兜底）。"""
    for cookie in client.cookies.jar:
        if cookie.name == "login_session":
            val = cookie.value or ""
            parts = val.split(".")
            if not parts:
                continue
            b64 = parts[0]
            pad = "=" * (-len(b64) % 4)
            try:
                payload = json.loads(
                    base64.urlsafe_b64decode(b64 + pad).decode("utf-8")
                )
                lv = str(payload.get("login_challenge") or "")
                if lv:
                    return lv
            except Exception:  # noqa: BLE001
                continue
    return ""


async def _chase_oauth2_auth_with_login_verifier(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    login_verifier: str = "",
    pkce_challenge: str = "",
    state_val: str = "",
    max_hops: int = 15,
    log=None,
) -> str:
    """A 版 _follow_redirect_chain：跳 oauth2/auth，跟随 redirect 拿 code。

    login_verifier 可空。若空则用原始 pkce_challenge + state（OpenAI server-side 仍认识）。
    """
    consent_referer = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"
    params: dict[str, str] = {
        "client_id": CHATGPT_CLIENT_ID,
        "code_challenge_method": "S256",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
        "redirect_uri": CHATGPT_REDIRECT_URI,
        "response_type": "code",
        "scope": CHATGPT_SCOPE,
    }
    if pkce_challenge:
        params["code_challenge"] = pkce_challenge
    if state_val:
        params["state"] = state_val
    if login_verifier:
        params["login_verifier"] = login_verifier
    else:
        params["prompt"] = "login"
    oauth2_url = f"{AUTH_BASE}/api/oauth/oauth2/auth?{urllib.parse.urlencode(params)}"

    nav_h = nav_headers(profile, device_id, site="same-origin")
    nav_h["Referer"] = consent_referer

    cur_url = oauth2_url
    last_url = cur_url
    for _hop in range(max_hops):
        if cur_url.startswith(CHATGPT_REDIRECT_URI):
            code = _pick_code_from_url(cur_url)
            if code:
                return code
            if log is not None:
                try:
                    log(f"🔎 [Codex] oauth2/auth 回到 callback 但无 code: {cur_url[:120]}")
                except Exception:  # noqa: BLE001
                    pass
            return ""
        last_url = cur_url
        resp = await request_with_retry(
            client, "GET", cur_url, headers=nav_h,
            follow_redirects=False, retries=2,
        )
        loc = (resp.headers.get("Location") or "").strip()
        if resp.status_code in (301, 302, 303, 307, 308) and loc:
            if loc.startswith("/"):
                loc = AUTH_BASE + loc
            if loc.startswith(CHATGPT_REDIRECT_URI):
                code = _pick_code_from_url(loc)
                if code:
                    return code
                if log is not None:
                    try:
                        log(f"🔎 [Codex] oauth2/auth Location callback 无 code: {loc[:120]}")
                    except Exception:  # noqa: BLE001
                        pass
                return ""
            cur_url = loc
            continue
        if resp.status_code == 200:
            try:
                body = resp.json()
                redir = body.get("redirect_url") or body.get("continue_url") or ""
                if redir:
                    cur_url = redir
                    continue
            except Exception:  # noqa: BLE001
                pass
        break
    if log is not None:
        try:
            log(f"🔎 [Codex] oauth2/auth 未拿到 code，最后: {last_url[:120]}")
        except Exception:  # noqa: BLE001
            pass
    return ""


# -----------------------------------------------------------------------------
# Email-OTP-after fallback：A 版的 session_dump → workspace/select → organization/select 链路
# -----------------------------------------------------------------------------


async def _email_otp_post_validate_chain(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    pkce_challenge: str = "",
    state_val: str = "",
) -> str:
    """OTP 验证通过后，走 A 版完整链路拿 ?code=。

    1) GET  /api/accounts/client_auth_session_dump  → workspace_id
    2) POST /api/accounts/workspace/select          → continue_url（可能含 /codex/organization）
    3) 若需要选 org: GET /sign-in-with-chatgpt/codex/organization → POST /api/accounts/organization/select
    4) 任何一步返回的 continue_url 命中 localhost:1455/auth/callback?code= → 提 code

    返回空串则表示这条 fallback 也没拿到 code。
    """
    consent_referer = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

    # 1) session_dump
    nav_h = nav_headers(profile, device_id, site="same-origin")
    nav_h["Referer"] = f"{AUTH_BASE}/email-verification"
    nav_h["Accept"] = "application/json, text/plain, */*"
    resp = await request_with_retry(
        client, "GET",
        f"{AUTH_BASE}/api/accounts/client_auth_session_dump",
        headers=nav_h, follow_redirects=False, retries=2,
    )
    workspace_id = ""
    if resp.status_code == 200:
        try:
            data = resp.json()
            for src in (data, (data or {}).get("client_auth_session") or {}):
                if isinstance(src, dict):
                    ws = src.get("workspaces")
                    if isinstance(ws, list) and ws and isinstance(ws[0], dict):
                        workspace_id = str(ws[0].get("id") or "")
                        if workspace_id:
                            break
        except Exception:  # noqa: BLE001
            pass
    if not workspace_id:
        workspace_id = _extract_workspace_id_from_session_cookie(client)

    # 没 workspace_id 时，A 版兜底：
    #   1) 先试 login_session cookie 拿 login_verifier 跳 oauth2/auth
    #   2) 仍没有 → 用原始 pkce_challenge + state 直接打 oauth2/auth（OpenAI 用 server-side 已存 state）
    if not workspace_id:
        lv = _extract_login_verifier_from_cookie(client)
        code = await _chase_oauth2_auth_with_login_verifier(
            client, profile=profile, device_id=device_id,
            login_verifier=lv,
            pkce_challenge=pkce_challenge, state_val=state_val,
        )
        return code

    # 2) workspace/select
    json_h = json_headers(profile, device_id, referer=consent_referer)
    resp = await request_with_retry(
        client, "POST",
        f"{AUTH_BASE}/api/accounts/workspace/select",
        json={"workspace_id": workspace_id},
        headers=json_h, follow_redirects=False, retries=2,
    )
    if resp.status_code not in (200, 201, 204, 302, 303, 307, 308):
        return ""
    try:
        ws_body = resp.json() if resp.text else {}
    except Exception:  # noqa: BLE001
        ws_body = {}

    # workspace/select 自身可能直接返回 callback URL 含 code
    if isinstance(ws_body, dict):
        for key in ("continue_url", "redirect_url", "url"):
            val = ws_body.get(key)
            if isinstance(val, str) and val.startswith(CHATGPT_REDIRECT_URI):
                c = _pick_code_from_url(val)
                if c:
                    return c

    continue_url_after_ws = ""
    if isinstance(ws_body, dict):
        for key in ("continue_url", "redirect_url", "url"):
            v = ws_body.get(key)
            if isinstance(v, str) and v:
                continue_url_after_ws = v
                break

    # 3) 需要选 organization
    if continue_url_after_ws and "/codex/organization" in continue_url_after_ws:
        nav_h2 = nav_headers(profile, device_id, site="same-origin")
        nav_h2["Referer"] = consent_referer
        await request_with_retry(
            client, "GET", continue_url_after_ws, headers=nav_h2,
            follow_redirects=True, retries=2,
        )

        orgs: list[dict[str, Any]] = []
        data = ws_body.get("data") if isinstance(ws_body, dict) else None
        if isinstance(data, dict):
            raw = data.get("orgs")
            if isinstance(raw, list):
                orgs = [o for o in raw if isinstance(o, dict)]
        if not orgs and isinstance(ws_body, dict):
            raw = ws_body.get("orgs")
            if isinstance(raw, list):
                orgs = [o for o in raw if isinstance(o, dict)]

        org = None
        for o in orgs:
            if (o.get("kind") or "").lower() == "personal":
                org = o
                break
        if not org and orgs:
            org = orgs[0]
        if not org:
            return ""

        org_id = str(org.get("id") or "")
        project_id = ""
        projs = org.get("projects") or []
        if isinstance(projs, list) and projs and isinstance(projs[0], dict):
            project_id = str(projs[0].get("id") or "")
        if not project_id:
            project_id = str(org.get("default_project_id") or org.get("project_id") or "")

        payload: dict[str, str] = {"org_id": org_id}
        if project_id:
            payload["project_id"] = project_id
        json_h2 = json_headers(profile, device_id, referer=continue_url_after_ws)
        resp_org = await request_with_retry(
            client, "POST",
            f"{AUTH_BASE}/api/accounts/organization/select",
            json=payload,
            headers=json_h2, follow_redirects=False, retries=2,
        )
        if resp_org.status_code not in (200, 201, 204, 302, 303, 307, 308):
            return ""
        try:
            org_body = resp_org.json() if resp_org.text else {}
        except Exception:  # noqa: BLE001
            org_body = {}

        if isinstance(org_body, dict):
            for key in ("continue_url", "redirect_url", "url"):
                val = org_body.get(key)
                if isinstance(val, str) and val.startswith(CHATGPT_REDIRECT_URI):
                    c = _pick_code_from_url(val)
                    if c:
                        return c
            # 若返回 login_verifier，走 oauth2/auth chase
            for key in ("continue_url", "redirect_url", "url"):
                val = org_body.get(key)
                if isinstance(val, str) and val:
                    c, _ = await chase_to_localhost_code(
                        client, profile=profile, device_id=device_id,
                        start_url=val, max_hops=12,
                    )
                    if c:
                        return c
                    break

    return ""


# -----------------------------------------------------------------------------
# Step 5: POST /api/accounts/workspace/select
# -----------------------------------------------------------------------------


async def submit_codex_consent(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    consent_url: str,
    pkce_challenge: str = "",
    state_val: str = "",
    log=None,
) -> tuple[str, list[dict[str, Any]]]:
    """提交 codex consent 表单。

    Returns:
        (next_url, orgs)。next_url 多半是 .../codex/organization；
        orgs 是 response.data.orgs 数组，下一步 organization/select 用。
    """
    nav_h = nav_headers(profile, device_id, site="same-origin")
    nav_h["Referer"] = f"{AUTH_BASE}/"
    # 触一下 consent HTML 让 session 数据刷新（顺便 cookie 更新）
    await request_with_retry(
        client, "GET", consent_url, headers=nav_h,
        follow_redirects=True, retries=2,
    )

    ws_id = _extract_workspace_id_from_session_cookie(client)
    if not ws_id:
        raise RuntimeError("oai-client-auth-session cookie 里没找到 workspaces[0].id")

    api_url = f"{AUTH_BASE}/api/accounts/workspace/select"
    json_h = json_headers(profile, device_id, referer=consent_url)
    resp = await request_with_retry(
        client, "POST", api_url,
        json={"workspace_id": ws_id},
        headers=json_h,
        follow_redirects=False,
        retries=2,
    )
    if resp.status_code == 400 and "duplicate" in (resp.text or "").lower():
        login_verifier = _extract_login_verifier_from_cookie(client)
        code = await _chase_oauth2_auth_with_login_verifier(
            client,
            profile=profile,
            device_id=device_id,
            login_verifier=login_verifier,
            pkce_challenge=pkce_challenge,
            state_val=state_val,
            log=log,
        )
        if code:
            return f"{CHATGPT_REDIRECT_URI}?code={code}", []

        dump = await _client_auth_session_dump(
            client,
            profile=profile,
            device_id=device_id,
            referer=consent_url,
        )
        orgs = _extract_orgs_from_client_auth_payload(dump)
        if not orgs:
            orgs = _extract_orgs_from_client_auth_payload(
                _extract_client_auth_payload_from_cookie(client)
            )
        if orgs:
            if log is not None:
                try:
                    first = orgs[0]
                    projs = first.get("projects") if isinstance(first.get("projects"), list) else []
                    log(
                        "🔎 [Codex] workspace/select duplicate，"
                        f"session_dump orgs={len(orgs)} "
                        f"keys={','.join(sorted(str(k) for k in first.keys())[:12])} "
                        f"id={str(first.get('id') or '')[:48]} "
                        f"kind={first.get('kind') or ''} "
                        f"default_project_id={str(first.get('default_project_id') or '')[:48]} "
                        f"projects={len(projs)}"
                    )
                except Exception:  # noqa: BLE001
                    pass
            return f"{AUTH_BASE}/sign-in-with-chatgpt/codex/organization", orgs

        if log is not None:
            try:
                log(
                    "🔎 [Codex] workspace/select duplicate，"
                    f"login_verifier={'yes' if login_verifier else 'no'}"
                )
            except Exception:  # noqa: BLE001
                pass
        return "", []
    if resp.status_code not in (200, 201, 204, 302, 303, 307, 308):
        raise RuntimeError(
            f"workspace/select HTTP {resp.status_code}: {resp.text[:300]}"
        )
    # 优先看 Location（302）
    loc = (resp.headers.get("Location") or "").strip()
    if loc:
        return loc, []
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {}
    orgs: list[dict[str, Any]] = []
    next_url = ""
    if isinstance(body, dict):
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        if isinstance(data, dict):
            raw_orgs = data.get("orgs")
            if isinstance(raw_orgs, list):
                orgs = [o for o in raw_orgs if isinstance(o, dict)]
        for key in ("redirect_url", "redirectUrl", "continue_url", "continueUrl", "url"):
            val = body.get(key)
            if isinstance(val, str) and val:
                next_url = val
                break
        if not next_url and isinstance(data, dict):
            for key in ("redirect_url", "redirectUrl", "continue_url", "continueUrl", "url"):
                val = data.get(key)
                if isinstance(val, str) and val:
                    next_url = val
                    break
    return next_url, orgs


# -----------------------------------------------------------------------------
# Step 6: POST /api/accounts/organization/select
# -----------------------------------------------------------------------------


async def submit_codex_organization(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    org_id: str,
    project_id: str,
    referer_url: str,
    pkce_challenge: str = "",
    state_val: str = "",
    log=None,
) -> str:
    """提交 codex organization 选择，返回下一跳 URL（多半带 ?code=）。"""
    api_url = f"{AUTH_BASE}/api/accounts/organization/select"
    json_h = json_headers(profile, device_id, referer=referer_url)

    def _extract_next(resp: httpx.Response) -> str:
        loc = (resp.headers.get("Location") or "").strip()
        if loc:
            return loc
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            body = {}
        if isinstance(body, dict):
            for key in ("redirect_url", "redirectUrl", "continue_url", "continueUrl", "url"):
                val = body.get(key)
                if isinstance(val, str) and val:
                    return val
        return ""

    resp = await request_with_retry(
        client, "POST", api_url,
        json={"org_id": org_id, "project_id": project_id},
        headers=json_h,
        follow_redirects=False,
        retries=2,
    )
    if log is not None:
        try:
            loc_dbg = (resp.headers.get("Location") or "").strip()
            log(
                "🔎 [Codex] organization/select response "
                f"status={resp.status_code} "
                f"location={loc_dbg[:100] if loc_dbg else '-'} "
                f"body={(resp.text or '')[:180].replace(chr(10), ' ')}"
            )
        except Exception:  # noqa: BLE001
            pass
    duplicate_text = (resp.text or "").lower()
    if resp.status_code == 400 and "duplicate" in duplicate_text:
        if project_id and "default project" not in duplicate_text:
            retry_resp = await request_with_retry(
                client, "POST", api_url,
                json={"org_id": org_id},
                headers=json_h,
                follow_redirects=False,
                retries=2,
            )
            if log is not None:
                try:
                    loc_dbg = (retry_resp.headers.get("Location") or "").strip()
                    log(
                        "🔎 [Codex] organization/select retry without project "
                        f"status={retry_resp.status_code} "
                        f"location={loc_dbg[:100] if loc_dbg else '-'} "
                        f"body={(retry_resp.text or '')[:180].replace(chr(10), ' ')}"
                    )
                except Exception:  # noqa: BLE001
                    pass
            if retry_resp.status_code in (200, 201, 204, 302, 303, 307, 308):
                nxt = _extract_next(retry_resp)
                if nxt:
                    return nxt
        code = await _chase_oauth2_auth_with_login_verifier(
            client,
            profile=profile,
            device_id=device_id,
            login_verifier=_extract_login_verifier_from_cookie(client),
            pkce_challenge=pkce_challenge,
            state_val=state_val,
            log=log,
        )
        if code:
            return f"{CHATGPT_REDIRECT_URI}?code={code}"
        nxt = _extract_next(resp)
        return nxt or referer_url
    if resp.status_code not in (200, 201, 204, 302, 303, 307, 308):
        raise RuntimeError(
            f"organization/select HTTP {resp.status_code}: {resp.text[:300]}"
        )
    return _extract_next(resp)


# -----------------------------------------------------------------------------
# Step 7: POST /oauth/token
# -----------------------------------------------------------------------------


async def exchange_code_for_token(
    client: httpx.AsyncClient,
    *,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CHATGPT_REDIRECT_URI,
        "client_id": CHATGPT_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    body = urllib.parse.urlencode(form)
    resp = await request_with_retry(
        client, "POST",
        f"{AUTH_BASE}/oauth/token",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        },
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"oauth/token HTTP {resp.status_code}: {resp.text[:300]}"
        )
    return resp.json()


@dataclass(slots=True)
class AccountIdResult:
    """复用已登录 session 跑 Codex client authorize 的产出。"""

    access_token: str
    refresh_token: str
    id_token: str
    expires_in: int
    chatgpt_account_id: str
    chatgpt_user_id: str
    plan_type: str
    sub: str


async def fetch_account_id_via_session(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    email: str,
) -> AccountIdResult:
    """在「注册刚结束、仍登录着」的 session 里，用 Codex client 再 authorize 一次拿 token。

    关键：复用注册时种下的「已登录」cookie，不走密码登录（密码登录会撞 add_phone）。
    team 账号此时会自动加入 team，授权链路直接走通拿到 chatgpt_account_id。

    必须用与注册同一个 client（共享 cookie / UA / proxy）。
    """
    pkce = new_pkce()
    state, nonce = random_state_nonce()

    # 1) Codex client authorize（带已登录 cookie，多半半路就 307 到 callback?code=）
    code, last_loc = await chatgpt_authorize(
        client, profile=profile, device_id=device_id,
        pkce_challenge=pkce.challenge, state_val=state, nonce_val=nonce,
        email=email,
    )

    # 2) 没半路拿到 → chase consent / workspace / organization
    if not code:
        start = last_loc or f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"
        code, callback_url = await chase_to_localhost_code(
            client, profile=profile, device_id=device_id, start_url=start,
        )
        if not code and "/sign-in-with-chatgpt/" in (callback_url or start):
            consent_url = callback_url or start
            next_url, orgs = await submit_codex_consent(
                client,
                profile=profile,
                device_id=device_id,
                consent_url=consent_url,
                pkce_challenge=pkce.challenge,
                state_val=state,
            )
            if next_url:
                code = _pick_code_from_url(next_url)
                if not code and "/codex/organization" in next_url:
                    org = None
                    for o in orgs:
                        if (o.get("kind") or "").lower() == "personal":
                            org = o
                            break
                    if not org and orgs:
                        org = orgs[0]
                    if org:
                        org_id = str(org.get("id") or "")
                        project_id = ""
                        projects = org.get("projects") or []
                        if isinstance(projects, list) and projects and isinstance(projects[0], dict):
                            project_id = str(projects[0].get("id") or "")
                        if not project_id:
                            project_id = str(org.get("default_project_id") or org.get("project_id") or "")
                        org_next = await submit_codex_organization(
                            client, profile=profile, device_id=device_id,
                            org_id=org_id, project_id=project_id, referer_url=next_url,
                        )
                        if org_next:
                            code = _pick_code_from_url(org_next)
                            if not code:
                                code, _ = await chase_to_localhost_code(
                                    client, profile=profile, device_id=device_id, start_url=org_next,
                                )
                elif not code:
                    code, _ = await chase_to_localhost_code(
                        client, profile=profile, device_id=device_id, start_url=next_url,
                    )

    if not code:
        raise RuntimeError("session 复用 authorize 未拿到 ?code=（账号可能未进 team / 未登录）")

    # 3) 换 token + 解 claims
    tok = await exchange_code_for_token(client, code=code, code_verifier=pkce.verifier)
    at = (tok.get("access_token") or "").strip()
    rt = (tok.get("refresh_token") or "").strip()
    idt = (tok.get("id_token") or "").strip()
    expires_in = int(tok.get("expires_in") or 0)
    if not at:
        raise RuntimeError(f"Codex /oauth/token 没返 access_token: {tok}")
    claims = _jwt_claims(at)
    id_claims = _jwt_claims(idt)
    auth_info = claims.get("https://api.openai.com/auth") or {}
    return AccountIdResult(
        access_token=at,
        refresh_token=rt,
        id_token=idt,
        expires_in=expires_in,
        chatgpt_account_id=str(auth_info.get("chatgpt_account_id") or ""),
        chatgpt_user_id=str(auth_info.get("chatgpt_user_id") or ""),
        plan_type=str(auth_info.get("chatgpt_plan_type") or "plus"),
        sub=str(id_claims.get("sub") or claims.get("sub") or ""),
    )


# -----------------------------------------------------------------------------
# 顶层入口
# -----------------------------------------------------------------------------


async def login_get_tokens(
    *,
    email: str,
    password: str,
    proxy: Optional[str] = None,
    profile: Optional[Profile] = None,
    device_id: Optional[str] = None,
    otp_fetcher: Optional[OtpFetcher] = None,
    sms_fetcher: Optional[Callable[[], Awaitable[str]]] = None,
    on_step: Optional[Callable[[str, str], None]] = None,
) -> ChatGPTLoginResult:
    """协议方式拿 ChatGPT OAuth tokens（一站式）。

    Args:
        email: 账号邮箱
        password: 协议注册时设置的密码
        proxy: 代理 URL（http/socks5）；None = 直连
        profile: 浏览器指纹画像；None = 随机生成
        device_id: oai-device-id；None = 随机 UUID
        otp_fetcher: 撞 email_otp 二次验证时的回调，签名 (email) -> str；
                     None 时直接抛 EmailOtpRequiredError
        on_step: 进度回调，签名 (stage_key, message) -> None；用于 worker
                 emit_stage/emit_progress 上报

    Raises:
        EmailOtpRequiredError: 撞 OTP 但没提供 fetcher
        RuntimeError: 流程任何一步失败
    """
    started = time.time()

    def _step(key: str, msg: str) -> None:
        if on_step is not None:
            try:
                on_step(key, msg)
            except Exception:  # noqa: BLE001
                pass

    if not email or "@" not in email:
        raise RuntimeError("email 非法")
    if not password:
        raise RuntimeError("password 为空，协议登录无法继续")

    if profile is None:
        profile = random_profile()
    if device_id is None:
        device_id = new_device_id()
    pkce = new_pkce()
    state, nonce = random_state_nonce()
    sentinel = SentinelGenerator(device_id=device_id, user_agent=profile.user_agent)

    async with build_client(profile=profile, proxy=proxy) as client:
        # Step 2
        _step("authorize", "打开 OAuth 授权页")
        code, last_loc = await chatgpt_authorize(
            client,
            profile=profile, device_id=device_id,
            pkce_challenge=pkce.challenge,
            state_val=state, nonce_val=nonce,
            email=email,
        )

        # Step 3: 没拿到 code -> 密码登录
        continue_url = ""
        if not code:
            _step("password_verify", "提交密码登录")
            needs_otp, continue_url = await _password_verify(
                client, sentinel,
                profile=profile, device_id=device_id, password=password,
            )
            if needs_otp:
                _step("email_otp", "撞到 email_otp 二次验证")
                if otp_fetcher is None:
                    raise EmailOtpRequiredError(
                        "password/verify 后需要 email_otp 二次验证，但没提供 otp_fetcher"
                    )
                otp = (await otp_fetcher(email)).strip()
                if not otp:
                    raise RuntimeError("otp_fetcher 返回空 OTP")
                _step("email_otp_validate", "验证 email OTP")
                await _validate_email_otp(
                    client, sentinel,
                    profile=profile, device_id=device_id, otp=otp,
                )

            # Step 4: chase continue_url
            _step("chase", "chase consent / org 链路")
            code, callback_url = await chase_to_localhost_code(
                client, profile=profile, device_id=device_id,
                start_url=continue_url,
            )

            # Step 5: 卡在 consent -> POST workspace/select
            if not code and "/sign-in-with-chatgpt/" in (callback_url or continue_url):
                consent_url = callback_url or continue_url
                _step("consent_submit", "提交 codex consent")
                next_url, orgs = await submit_codex_consent(
                    client, profile=profile, device_id=device_id,
                    consent_url=consent_url,
                    pkce_challenge=pkce.challenge,
                    state_val=state,
                )
                if next_url:
                    code = _pick_code_from_url(next_url)
                    # Step 6: 还卡在 organization -> POST organization/select
                    if not code and "/codex/organization" in next_url:
                        org = None
                        for o in orgs:
                            if (o.get("kind") or "").lower() == "personal":
                                org = o
                                break
                        if not org and orgs:
                            org = orgs[0]
                        if not org:
                            raise RuntimeError("workspace/select 返回 orgs 为空，无法继续")
                        org_id = str(org.get("id") or "")
                        projects = org.get("projects") or []
                        project_id = ""
                        if isinstance(projects, list) and projects:
                            first_proj = projects[0]
                            if isinstance(first_proj, dict):
                                project_id = str(first_proj.get("id") or "")
                        if not project_id:
                            project_id = str(
                                org.get("default_project_id")
                                or org.get("project_id")
                                or ""
                            )
                        _step("org_select", "提交 codex organization")
                        org_next = await submit_codex_organization(
                            client, profile=profile, device_id=device_id,
                            org_id=org_id, project_id=project_id,
                            referer_url=next_url,
                        )
                        if org_next:
                            code = _pick_code_from_url(org_next)
                            if not code:
                                code, _ = await chase_to_localhost_code(
                                    client, profile=profile, device_id=device_id,
                                    start_url=org_next,
                                )
                    elif not code:
                        code, _ = await chase_to_localhost_code(
                            client, profile=profile, device_id=device_id,
                            start_url=next_url,
                        )

        # Fallback：撞了 email_otp 但 chase 卡在 /email-verification HTML 页时，
        # 走 A 版完整链路 session_dump → workspace/select → organization/select。
        if not code:
            cb = callback_url or continue_url or ""
            if "/email-verification" in cb or "/email-otp" in cb:
                _step("session_dump_chain", "走 session_dump 拿 workspace_id → organization 选择")
                code = await _email_otp_post_validate_chain(
                    client, profile=profile, device_id=device_id,
                    pkce_challenge=pkce.challenge, state_val=state,
                )

        if not code:
            raise RuntimeError("全流程跑完仍未拿到 ?code= 回调")

        # Step 7: 兑换 token
        _step("token_exchange", "兑换 access/refresh/id_token")
        tok = await exchange_code_for_token(
            client, code=code, code_verifier=pkce.verifier,
        )
        at = (tok.get("access_token") or "").strip()
        rt = (tok.get("refresh_token") or "").strip()
        idt = (tok.get("id_token") or "").strip()
        expires_in = int(tok.get("expires_in") or 0)
        if not at:
            raise RuntimeError(f"/oauth/token 没返 access_token: {tok}")

        claims = _jwt_claims(at)
        auth_info = claims.get("https://api.openai.com/auth") or {}
        sub_claim = str(claims.get("sub") or "")
        chatgpt_account_id = str(auth_info.get("chatgpt_account_id") or "")
        chatgpt_user_id = str(auth_info.get("chatgpt_user_id") or "")
        plan_type = str(auth_info.get("chatgpt_plan_type") or "plus")

        return ChatGPTLoginResult(
            email=email,
            access_token=at,
            id_token=idt,
            refresh_token=rt,
            expires_in=expires_in,
            chatgpt_account_id=chatgpt_account_id,
            chatgpt_user_id=chatgpt_user_id,
            plan_type=plan_type,
            sub=sub_claim,
            duration_seconds=time.time() - started,
            device_id=device_id,
            proxy_used=proxy,
        )


__all__ = [
    "CHATGPT_CLIENT_ID",
    "CHATGPT_REDIRECT_URI",
    "CHATGPT_SCOPE",
    "ChatGPTLoginResult",
    "EmailOtpRequiredError",
    "OtpFetcher",
    "chatgpt_authorize",
    "chase_to_localhost_code",
    "submit_codex_consent",
    "submit_codex_organization",
    "exchange_code_for_token",
    "login_get_tokens",
]
