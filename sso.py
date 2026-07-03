"""OpenAI SAML SSO 协议流程（纯 HTTP，无浏览器）。

让注册好的 team 域名账号通过 SSO 登录 → 进 team。流程从 OpenAI 的 ChatGPT web
client authorize 发起，经自建 Authentik（免密 passthrough）签发 SAMLResponse，
回到 OpenAI 完成登录。全程在同一个 httpx client（共享 cookie）里。

完整链路（从真实 HAR 还原）：
  1. GET  auth.openai.com/api/accounts/authorize?client_id=<WEB>&login_hint=<email>&state=<S>...
          → 302 /sso
  2. POST auth.openai.com/api/accounts/authorize/continue
          json={"connection":"<CONN>","connection_provider":2}
          → {"continue_url": "https://external.auth.openai.com/sso/authorize?..."}
  3. GET  continue_url → 302 到 Authentik /application/saml/openai/sso/binding/redirect/?SAMLRequest=..
  4. Authentik：未登录跳 sso-passthrough flow → 提交邮箱本地名免密登录
     → consent → autosubmit form（含 SAMLResponse + RelayState，action=ACS）
  5. POST external.auth.openai.com/sso/saml/acs/<id>  data={SAMLResponse, RelayState}
          → 302 /sso/signin-consent?token=...
  6. GET  /sso/signin-consent?token=... → 解出 interstitial_token + csrf_token
  7. POST external.auth.openai.com/sso/interstitial
          data={interstitial_token, action:"confirm", csrf_token}
          → 302 auth.openai.com/api/accounts/callback/workos?code=..&state=..
  8. GET  callback/workos → 账号进 team，session 完成
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from .core.http_client import AUTH_BASE, nav_headers, request_with_retry
from .core.profile import Profile

logger = logging.getLogger(__name__)

EXTERNAL_AUTH = "https://external.auth.openai.com"

# ChatGPT web client（HAR 实测，发起 SSO 用这个，不是 platform/codex client）
SSO_WEB_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
SSO_WEB_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"
SSO_WEB_SCOPE = (
    "openid email profile offline_access model.request model.read "
    "organization.read organization.write"
)


@dataclass(slots=True)
class AuthentikConfig:
    base_url: str = "https://sso.example.com"   # Authentik 对外地址
    app_slug: str = "openai"                     # SAML application slug
    passthrough_flow: str = "sso-passthrough"    # 免密登录 flow slug
    connection_id: str = ""                      # OpenAI SSO connection id（conn_...）


_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r'\baction="([^"]*)"', re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_NAME_RE = re.compile(r'\bname="([^"]+)"', re.IGNORECASE)
_VALUE_RE = re.compile(r'\bvalue="([^"]*)"', re.IGNORECASE)


def _parse_form(body: str, *, must_have: str = "") -> tuple[str, dict[str, str]]:
    """解析 HTML 里第一个含 must_have 字段的 form，返回 (action, {字段})。"""
    for form in _FORM_RE.findall(body):
        am = _ACTION_RE.search(form)
        action = html.unescape(am.group(1)) if am else ""
        fields: dict[str, str] = {}
        for tag in _INPUT_RE.findall(form):
            n = _NAME_RE.search(tag)
            v = _VALUE_RE.search(tag)
            if n:
                fields[html.unescape(n.group(1))] = html.unescape(v.group(1)) if v else ""
        if not must_have or must_have in fields:
            return action, fields
    return "", {}


# ---------------------------------------------------------------------------
# Authentik 免密登录 + SAML 链
# ---------------------------------------------------------------------------


async def _passthrough_login(
    client: httpx.AsyncClient, cfg: AuthentikConfig, *, email: str, next_url: str = "",
    log=None,
) -> None:
    """跑 sso-passthrough flow 免密登录（提交邮箱本地名）。"""
    base = cfg.base_url.rstrip("/")
    executor = f"{base}/api/v3/flows/executor/{cfg.passthrough_flow}/"
    next_value = _authentik_next_value(base, next_url)
    query = urlencode({"next": next_value}) if next_value else ""
    params = {"query": query}
    flow_referer = (
        f"{base}/if/flow/{cfg.passthrough_flow}/?{urlencode({'next': next_value})}"
        if next_value else f"{base}/if/flow/{cfg.passthrough_flow}/"
    )

    r = await client.get(
        executor,
        params=params,
        headers={"Accept": "*/*", "Referer": flow_referer},
        follow_redirects=False,
    )
    if r.status_code != 200:
        raise RuntimeError(f"passthrough GET HTTP {r.status_code}: {r.text[:200]}")
    try:
        comp = (r.json() or {}).get("component", "")
    except Exception:  # noqa: BLE001
        comp = ""

    for _ in range(6):
        csrf = client.cookies.get("authentik_csrf") or ""
        if comp == "ak-stage-prompt":
            payload = {"component": "ak-stage-prompt", "username": _authentik_username(email)}
        elif comp in ("xak-flow-redirect", "ak-stage-access-denied", ""):
            return
        else:
            payload = {"component": comp}
        r = await client.post(
            executor, params=params,
            headers={"Accept": "*/*", "Content-Type": "application/json",
                     "Origin": base, "X-Authentik-CSRF": csrf, "Referer": flow_referer},
            json=payload,
            follow_redirects=False,
        )
        for _redirect in range(4):
            loc = r.headers.get("location", "")
            if not loc:
                break
            follow_url = loc if loc.startswith("http") else urljoin(base, loc)
            r = await client.get(
                follow_url,
                headers={"Accept": "*/*", "X-Authentik-CSRF": csrf, "Referer": flow_referer},
                follow_redirects=False,
            )
        try:
            comp = (r.json() or {}).get("component", "")
        except Exception:  # noqa: BLE001
            return
    return


def _authentik_username(email: str) -> str:
    if "@" in email:
        return email.split("@", 1)[0]
    return email


def _authentik_next_value(base: str, next_url: str) -> str:
    """Authentik 前端传给 executor 的 next 是同域相对 URL。"""
    if not next_url:
        return ""
    parsed = urlparse(next_url)
    base_parsed = urlparse(base)
    if parsed.netloc and parsed.netloc == base_parsed.netloc:
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return next_url


def _safe_url_label(url: str) -> str:
    try:
        parsed = urlparse(url)
        return f"{parsed.netloc}{parsed.path}"
    except Exception:  # noqa: BLE001
        return url[:120]


async def _authentik_chase_to_acs_post(
    client: httpx.AsyncClient, cfg: AuthentikConfig, *, email: str, binding_url: str,
    max_hops: int = 14, log=None,
) -> str:
    """从 Authentik binding URL 出发，登录 + chase，最终把 SAMLResponse POST 到 OpenAI ACS。

    返回 ACS POST 后的 302 Location（指向 /sso/signin-consent?token=...）。
    """
    base = cfg.base_url.rstrip("/")

    cur = binding_url
    for hop in range(max_hops):
        r = await request_with_retry(
            client, "GET", cur,
            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Referer": base + "/"},
            follow_redirects=False,
        )
        loc = r.headers.get("location", "")

        if loc:
            cur = loc if loc.startswith("http") else urljoin(cur, loc)
            continue

        # 200：可能是 SPA flow 页（需走 executor）或 autosubmit form
        body = r.text or ""
        action, fields = _parse_form(body, must_have="SAMLResponse")
        if action and "SAMLResponse" in fields:
            acs_url = action if action.startswith("http") else urljoin(cur, action)
            r2 = await request_with_retry(
                client, "POST", acs_url,
                content=urlencode({k: fields[k] for k in ("SAMLResponse", "RelayState") if k in fields}),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Origin": base, "Referer": base + "/",
                         "Accept": "text/html,*/*;q=0.8"},
                follow_redirects=False,
            )
            loc2 = r2.headers.get("location", "")
            if loc2:
                return loc2 if loc2.startswith("http") else urljoin(acs_url, loc2)
            return str(r2.url)

        # SPA flow 页：用 executor 驱动 implicit-consent 完成
        if "/if/flow/" in cur:
            slug_m = re.search(r"/if/flow/([^/]+)/", cur)
            slug = slug_m.group(1) if slug_m else "default-provider-authorization-implicit-consent"
            if slug == cfg.passthrough_flow:
                await _passthrough_login(client, cfg, email=email, next_url=binding_url, log=log)
                cur = binding_url
                continue
            q = urlparse(cur).query
            ex = f"{base}/api/v3/flows/executor/{slug}/"
            for _ in range(6):
                rr = await client.get(ex, params={"query": q}, headers={"Accept": "application/json"})
                try:
                    dd = rr.json()
                except Exception:  # noqa: BLE001
                    break
                comp = dd.get("component", "")
                if comp == "xak-flow-redirect":
                    nxt = dd.get("to", "")
                    cur = nxt if nxt.startswith("http") else urljoin(base, nxt) if nxt else binding_url
                    break
                if comp == "ak-stage-autosubmit":
                    # executor 给了 autosubmit JSON：含 url + attrs(SAMLResponse/RelayState)
                    acs_url = dd.get("url", "")
                    attrs = dd.get("attrs", {}) or {}
                    if acs_url and "SAMLResponse" in attrs:
                        r2 = await request_with_retry(
                            client, "POST", acs_url,
                            content=urlencode({k: attrs[k] for k in ("SAMLResponse", "RelayState") if k in attrs}),
                            headers={"Content-Type": "application/x-www-form-urlencoded",
                                     "Origin": base, "Referer": base + "/", "Accept": "text/html,*/*;q=0.8"},
                            follow_redirects=False,
                        )
                        loc2 = r2.headers.get("location", "")
                        return (loc2 if loc2.startswith("http") else urljoin(acs_url, loc2)) if loc2 else str(r2.url)
                    break
                # consent stage：同意
                csrf = client.cookies.get("authentik_csrf") or ""
                await client.post(ex, params={"query": q},
                    headers={"Accept": "application/json", "Content-Type": "application/json",
                             "X-Authentik-CSRF": csrf, "Referer": base + "/"},
                    json={"component": comp})
            continue

        raise RuntimeError(f"Authentik chase 停在非预期页 (hop {hop}): {cur[:120]}")

    raise RuntimeError(f"Authentik chase 超过 {max_hops} 跳")


# ---------------------------------------------------------------------------
# OpenAI 侧 SSO 编排
# ---------------------------------------------------------------------------


def _secret_state() -> str:
    import secrets
    return secrets.token_urlsafe(24)


async def run_openai_sso(
    client: httpx.AsyncClient,
    cfg: AuthentikConfig,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str = "",
    state: str = "",
    nonce: str = "",
    log=None,
) -> str:
    """跑一次完整 OpenAI SSO（任意 client）。返回最终回调 URL。

    对 web client → 回 chatgpt.com/...callback；对 Codex client → 回
    localhost:1455/auth/callback?code=（调用方从中取 code）。

    每次都是从头完整 SSO（authorize → continue → Authentik passthrough 免密登录
    → SAMLResponse → ACS → signin-consent → interstitial → 回调），与你手动操作
    "分开的两次"一致。建议每次用全新 client（独立 cookie/device_id）。
    """
    info = log or (lambda s: logger.info(s))
    if not cfg.connection_id:
        raise RuntimeError("SSO 需要 connection_id（conn_...），未配置")

    base = cfg.base_url.rstrip("/")
    state = state or _secret_state()

    # Step 1: authorize → 302 /sso
    params = {
        "client_id": client_id,
        "scope": scope,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "audience": "https://api.openai.com/v1",
        "device_id": device_id,
        "prompt": "login",
        "ext-oai-did": device_id,
        "screen_hint": "login_or_signup",
        "login_hint": email,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    if nonce:
        params["nonce"] = nonce
    h = nav_headers(profile, device_id, site="same-origin")
    h["Referer"] = "https://chatgpt.com/"
    info("🔑 [SSO] authorize 发起 ...")
    await request_with_retry(
        client, "GET", f"{AUTH_BASE}/api/accounts/authorize?{urlencode(params)}",
        headers=h, follow_redirects=True,
    )

    # Step 2: authorize/continue 指定 connection → continue_url
    info("🔗 [SSO] 指定 connection，拿 continue_url ...")
    from .core.http_client import json_headers
    jh = json_headers(profile, device_id, f"{AUTH_BASE}/sso")
    r = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/authorize/continue",
        content=__import__("json").dumps(
            {"connection": cfg.connection_id, "connection_provider": 2}
        ),
        headers=jh, follow_redirects=False,
    )
    try:
        continue_url = (r.json() or {}).get("continue_url", "")
    except Exception:  # noqa: BLE001
        continue_url = ""
    continue_url = continue_url or r.headers.get("location", "")
    if not continue_url:
        raise RuntimeError(f"authorize/continue 没拿到 continue_url: {r.text[:200]}")

    # Step 3: GET continue_url → 302 到 Authentik binding
    info("➡️  [SSO] 跳转到 Authentik ...")
    binding_url = ""
    cur = continue_url
    for _ in range(6):
        rr = await request_with_retry(client, "GET", cur, headers=h, follow_redirects=False)
        loc = rr.headers.get("location", "")
        if not loc:
            break
        full = loc if loc.startswith("http") else urljoin(cur, loc)
        if base in full:
            binding_url = full
            break
        cur = full
    if not binding_url:
        raise RuntimeError("没跳到 Authentik binding URL")

    # Step 4+5: Authentik 免密登录 + chase + POST SAMLResponse → signin-consent
    info("🔐 [SSO] Authentik 免密登录 + 签发 SAMLResponse ...")
    consent_loc = await _authentik_chase_to_acs_post(
        client, cfg, email=email, binding_url=binding_url,
    )

    # Step 6: signin-consent → 解 interstitial_token + csrf_token
    info("📝 [SSO] 处理 signin-consent ...")
    rc = await request_with_retry(
        client, "GET", consent_loc,
        headers={"Accept": "text/html,*/*;q=0.8", "Referer": base + "/"},
        follow_redirects=True,
    )
    action, fields = _parse_form(rc.text or "", must_have="interstitial_token")
    if "interstitial_token" not in fields:
        raise RuntimeError(f"signin-consent 没解出 interstitial_token: {str(rc.url)[:120]}")
    fields.setdefault("action", "confirm")

    # Step 7: POST /sso/interstitial → 回调（含 code，对 Codex 是 localhost:1455?code=）
    action_url = action if action.startswith("http") else urljoin(str(rc.url), action or "/sso/interstitial")
    info("✅ [SSO] 提交 interstitial，完成回调 ...")
    ri = await request_with_retry(
        client, "POST", action_url,
        content=urlencode(fields),
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Origin": EXTERNAL_AUTH, "Referer": consent_loc, "Accept": "text/html,*/*;q=0.8"},
        follow_redirects=True,
    )
    return str(ri.url)


# 兼容旧名：纯登录进 team（web client）
async def sso_login_to_team(
    client: httpx.AsyncClient, cfg: AuthentikConfig, *,
    profile: Profile, device_id: str, email: str, log=None,
) -> None:
    await run_openai_sso(
        client, cfg, profile=profile, device_id=device_id, email=email,
        client_id=SSO_WEB_CLIENT_ID, redirect_uri=SSO_WEB_REDIRECT_URI,
        scope=SSO_WEB_SCOPE, log=log,
    )


# Codex CLI client（拿 chatgpt_account_id + refresh_token）
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid profile email offline_access"


async def _handle_add_phone(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    sms_provider,
    max_attempts: int = 3,
    log=None,
) -> str:
    """绑定手机号过 add-phone 墙，返回验证成功后的 continue_url（指向 consent）。

    链路（HAR 实测，纯 cookie 会话，无 sentinel）：
      1. sms_provider 取号 -> +E.164
      2. POST /api/accounts/add-phone/send   {phone_number, channel:"sms"}
      3. sms_provider 轮询拿 6 位码
      4. POST /api/accounts/phone-otp/validate {code} -> {continue_url}

    send 撞 OpenAI 风控（fraud_guard）时自动 release 当前号、换号重试，最多 max_attempts 次。
    """
    import json as _json
    from .core.http_client import json_headers, set_oai_did_cookie
    from .core.sentinel import SentinelGenerator

    set_oai_did_cookie(client, device_id)
    sentinel = SentinelGenerator(
        device_id=device_id,
        user_agent=profile.user_agent,
        language=profile.locale.split(",", 1)[0],
    )

    info = log or (lambda s: logger.info(s))
    jh = json_headers(profile, device_id, f"{AUTH_BASE}/add-phone")
    jh2 = json_headers(profile, device_id, f"{AUTH_BASE}/phone-verification")
    last_err = ""

    for attempt in range(1, max_attempts + 1):
        number = await sms_provider.acquire_number(log=info)
        try:
            info(f"📞 [Codex] add-phone/send {number.phone_e164}（第 {attempt}/{max_attempts} 次）...")
            rs = await request_with_retry(
                client, "POST", f"{AUTH_BASE}/api/accounts/add-phone/send",
                content=_json.dumps({"phone_number": number.phone_e164, "channel": "sms"}),
                headers=jh, follow_redirects=False,
            )
            if rs.status_code != 200:
                body = rs.text or ""
                last_err = f"status={rs.status_code}: {body[:200]}"
                # 风控 / 号码被拒：换号重试
                if rs.status_code == 400 and ("fraud_guard" in body or "suspicious" in body):
                    info(f"⚠️  [Codex] 号 {number.phone_e164} 撞风控（fraud_guard），换号重试 ...")
                    await sms_provider.release(number.activation_id)
                    continue
                raise RuntimeError(f"[Codex] add-phone/send 失败 {last_err}")

            code = (await sms_provider.poll_code(number.activation_id, log=info)).strip()

            info("🔐 [Codex] phone-otp/validate ...")
            rv = await request_with_retry(
                client, "POST", f"{AUTH_BASE}/api/accounts/phone-otp/validate",
                content=_json.dumps({"code": code}),
                headers=jh2, follow_redirects=False,
            )
            if rv.status_code != 200:
                raise RuntimeError(f"[Codex] phone-otp/validate 失败 status={rv.status_code}: {rv.text[:200]}")
            try:
                cont = (rv.json() or {}).get("continue_url") or ""
            except Exception:  # noqa: BLE001
                cont = ""
            if not cont:
                raise RuntimeError(f"[Codex] phone-otp/validate 没返 continue_url: {rv.text[:200]}")
            info(f"✅ [Codex] 手机号绑定完成 → {cont[:90]}")
            await sms_provider.release(number.activation_id)
            return cont
        except Exception:
            await sms_provider.release(number.activation_id)
            raise

    raise RuntimeError(f"[Codex] add-phone 连续 {max_attempts} 次撞风控，放弃。最后: {last_err}")


async def codex_login_via_sso(
    client: httpx.AsyncClient,
    cfg: AuthentikConfig,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    code_challenge: str,
    state: str,
    sms_provider=None,
    continue_attempts: int | None = None,
    continue_retry_sleep: float | None = None,
    continue_retry_sleep_max: float | None = None,
    log=None,
) -> str:
    """Codex client 走 SSO 拿 ?code=（localhost:1455 回调）。

    sms_provider：可选的接码客户端（如 HeroSmsClient）。落点 /add-phone 时用它
    取号 + 收码自动绑手机号；为 None 时遇到 add-phone 直接抛错。

    正确链路（HAR 实测）：
      1. GET  /oauth/authorize?client_id=<CODEX>&redirect_uri=localhost:1455... → /choose-an-account
      2. POST /api/accounts/authorize/continue
              {"username":{"value":email,"kind":"email"},"screen_hint":"login_or_signup"}
      3. → external sso/authorize → Authentik binding → 免密登录 → SAMLResponse
      4. POST ACS → callback/workos?code= → consent → workspace/select → localhost?code=
    返回 Codex 回调里的 ?code=。
    """
    info = log or (lambda s: logger.info(s))
    base = cfg.base_url.rstrip("/")
    from urllib.parse import parse_qs
    import json as _json
    from .core.http_client import json_headers, set_oai_did_cookie
    from .core.sentinel import SentinelGenerator

    set_oai_did_cookie(client, device_id)
    sentinel = SentinelGenerator(
        device_id=device_id,
        user_agent=profile.user_agent,
        language=profile.locale.split(",", 1)[0],
    )

    # Step 1: /oauth/authorize（Codex）
    params = {
        "response_type": "code",
        "client_id": CODEX_CLIENT_ID,
        "redirect_uri": CODEX_REDIRECT_URI,
        "scope": CODEX_SCOPE,
        "audience": "https://api.openai.com/v1",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "device_id": device_id,
        "prompt": "login",
        "login_hint": email,
    }
    h = nav_headers(profile, device_id, site="same-origin")
    h["Referer"] = "https://chatgpt.com/"
    info("🔑 [Codex] /oauth/authorize 发起 ...")
    await request_with_retry(
        client, "GET", f"{AUTH_BASE}/oauth/authorize?{urlencode(params)}",
        headers=h, follow_redirects=True,
    )

    # Step 2a: authorize/continue（username/email 形式）。
    # 只局部重试“提交 email”这一步；拿到 /sso 后再单独提交 connection。
    info("🔗 [Codex] authorize/continue（指定 email）...")
    continue_url = ""
    last_hint = ""
    max_continue_attempts = max(1, int(continue_attempts or os.environ.get("CODEX_AUTHORIZE_CONTINUE_ATTEMPTS", "3") or 3))
    base_continue_sleep = float(continue_retry_sleep if continue_retry_sleep is not None else (os.environ.get("CODEX_AUTHORIZE_CONTINUE_RETRY_SLEEP", "0") or 0))
    max_continue_sleep = float(continue_retry_sleep_max if continue_retry_sleep_max is not None else (os.environ.get("CODEX_AUTHORIZE_CONTINUE_RETRY_SLEEP_MAX", "0") or 0))
    for attempt in range(1, max_continue_attempts + 1):
        if attempt > 1:
            sleep_s = min(base_continue_sleep * attempt, max_continue_sleep)
            info(f"🔁 [Codex] authorize/continue email 重试 {attempt}/{max_continue_attempts} sleep={sleep_s:.1f}s ...")
            if sleep_s > 0:
                await asyncio.sleep(sleep_s)

        jh = json_headers(profile, device_id, f"{AUTH_BASE}/choose-an-account")
        jh["openai-sentinel-token"] = await sentinel.sentinel_token(
            client, "authorize_continue",
        )
        r = await request_with_retry(
            client, "POST", f"{AUTH_BASE}/api/accounts/authorize/continue",
            content=_json.dumps({
                "username": {"value": email, "kind": "email"},
                "screen_hint": "login_or_signup",
            }),
            headers=jh, follow_redirects=False,
        )
        try:
            cj = r.json() or {}
        except Exception:  # noqa: BLE001
            cj = {}
        continue_url = cj.get("url") or cj.get("continue_url") or r.headers.get("location", "") or ""
        last_hint = continue_url or (r.text or "")[:120]

        # email 这步只要拿到可继续的 URL（通常是 /sso），就停止 email 重试。
        if continue_url:
            break

    if not continue_url:
        raise RuntimeError(f"[Codex] authorize/continue email 没拿到 sso url: {last_hint[:120]}")

    # Step 2b: 若 email 只拿到 /sso，再 POST connection → external sso/authorize。
    # HAR 实测：connection 第一次可能 403 Access denied；网页会回到 GET /sso，
    # 然后再次 POST 同一个 connection 成功。因此这里重试 connection，且每次失败后补 GET /sso。
    if "external.auth.openai.com" not in continue_url:
        connection_attempts = max(1, int(os.environ.get("CODEX_CONNECTION_CONTINUE_ATTEMPTS", "3") or 3))
        for conn_attempt in range(1, connection_attempts + 1):
            if conn_attempt > 1:
                info(f"🔁 [Codex] authorize/continue connection 重试 {conn_attempt}/{connection_attempts}，先刷新 /sso ...")
                try:
                    await request_with_retry(
                        client, "GET", f"{AUTH_BASE}/sso",
                        headers=h, follow_redirects=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    last_hint = f"refresh /sso failed: {exc}"

            info("🔗 [Codex] authorize/continue（指定 connection）...")
            jh2 = json_headers(profile, device_id, f"{AUTH_BASE}/sso")
            jh2["openai-sentinel-token"] = await sentinel.sentinel_token(
                client, "authorize_continue",
            )
            r2 = await request_with_retry(
                client, "POST", f"{AUTH_BASE}/api/accounts/authorize/continue",
                content=_json.dumps({"connection": cfg.connection_id, "connection_provider": 2}),
                headers=jh2, follow_redirects=False,
            )
            try:
                cj2 = r2.json() or {}
            except Exception:  # noqa: BLE001
                cj2 = {}
            continue_url = cj2.get("url") or cj2.get("continue_url") or r2.headers.get("location", "")
            last_hint = continue_url or (r2.text or "")[:120] or last_hint
            if "external.auth.openai.com" in continue_url:
                break

    if not continue_url or "external.auth.openai.com" not in continue_url:
        raise RuntimeError(f"[Codex] authorize/continue connection 没拿到 external sso url: {last_hint[:120]}")

    # Step 3: GET continue_url → Authentik binding
    info("➡️  [Codex] 跳 Authentik ...")
    binding_url = ""
    cur = continue_url
    for _ in range(6):
        rr = await request_with_retry(client, "GET", cur, headers=h, follow_redirects=False)
        loc = rr.headers.get("location", "")
        if not loc:
            break
        full = loc if loc.startswith("http") else urljoin(cur, loc)
        if base in full:
            binding_url = full
            break
        cur = full
    if not binding_url:
        raise RuntimeError("[Codex] 没跳到 Authentik binding")

    # Step 4: Authentik 登录 + SAMLResponse POST → callback/workos 的 Location
    info("🔐 [Codex] Authentik 免密登录 + SAMLResponse ...")
    workos_loc = await _authentik_chase_to_acs_post(
        client, cfg, email=email, binding_url=binding_url, log=log,
    )
    info(f"↩️  [Codex] ACS 后回调: {workos_loc[:90]}")

    from .chatgpt_login import (
        chase_to_localhost_code, submit_codex_consent, submit_codex_organization,
        _pick_code_from_url,
    )

    # Step 4.5: 首次登录会经 signin-consent + interstitial，先过这一关
    if "/sso/signin-consent" in workos_loc:
        info("📝 [Codex] 处理 signin-consent + interstitial ...")
        rc = await request_with_retry(
            client, "GET", workos_loc,
            headers={"Accept": "text/html,*/*;q=0.8", "Referer": base + "/"},
            follow_redirects=True,
        )
        action, fields = _parse_form(rc.text or "", must_have="interstitial_token")
        if "interstitial_token" in fields:
            fields.setdefault("action", "confirm")
            au = action if action.startswith("http") else urljoin(str(rc.url), action or "/sso/interstitial")
            ri = await request_with_retry(
                client, "POST", au, content=urlencode(fields),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Origin": EXTERNAL_AUTH, "Referer": workos_loc, "Accept": "text/html,*/*;q=0.8"},
                follow_redirects=False,
            )
            nxt = ri.headers.get("location", "") or str(ri.url)
            workos_loc = nxt if nxt.startswith("http") else urljoin(au, nxt)
            info(f"↩️  [Codex] interstitial 后: {workos_loc[:90]}")

    # Step 5: 跟 callback/workos → consent → workspace/select → localhost?code=
    code = _pick_code_from_url(workos_loc)
    if code and "localhost:1455" in workos_loc:
        return code

    info("🧭 [Codex] 完成 workos 回调 → consent ...")
    target = workos_loc
    # callback/workos?code= ：GET 跟随，让 OpenAI 完成 SSO 登录并跳到 codex consent
    if "callback/workos" in workos_loc:
        nh = nav_headers(profile, device_id, site="same-origin")
        nh["Referer"] = EXTERNAL_AUTH + "/"
        for attempt in range(4):
            rc = await request_with_retry(
                client, "GET", target, headers=nh, follow_redirects=True,
            )
            target = str(rc.url)
            info(f"↩️  [Codex] workos 后落点: {target[:90]}")
            c2 = _pick_code_from_url(target)
            if c2 and "localhost:1455" in target:
                return c2
            if "callback/workos" not in target and rc.status_code < 500:
                break
            if attempt < 3:
                await asyncio.sleep(0.8)

    # add-phone 墙：OpenAI 要求绑定手机号。用 sms_provider 取号 + 收码自动过。
    if "/add-phone" in target:
        if sms_provider is None:
            raise RuntimeError(
                f"[Codex] 撞 add-phone 墙（账号要求绑定手机号），未配置 sms_provider: {target[:120]}"
            )
        target = await _handle_add_phone(
            client, profile=profile, device_id=device_id,
            sms_provider=sms_provider, log=info,
        )

    if "/sign-in-with-chatgpt/" in target or "consent" in target:
        next_url, orgs = await submit_codex_consent(
            client,
            profile=profile,
            device_id=device_id,
            consent_url=target,
            pkce_challenge=code_challenge,
            state_val=state,
            log=info,
        )
        if next_url:
            code = _pick_code_from_url(next_url)
            if code:
                return code
            if "/codex/organization" in next_url and orgs:
                org = next(
                    (o for o in orgs if (o.get("kind") or "").lower() != "personal"),
                    orgs[0],
                )
                org_id = str(org.get("id") or "")
                projs = org.get("projects") or []
                pid = str(projs[0].get("id")) if projs and isinstance(projs[0], dict) else str(org.get("default_project_id") or "")
                info(
                    "🔎 [Codex] organization/select "
                    f"org_id={org_id[:48]} project_id={pid[:48]} "
                    f"kind={org.get('kind') or ''} "
                    f"org_keys={','.join(sorted(str(k) for k in org.keys())[:16])} "
                    f"default_project_id={str(org.get('default_project_id') or '')[:48]} "
                    f"project_id={str(org.get('project_id') or '')[:48]} "
                    f"projects={len(projs) if isinstance(projs, list) else 0}"
                )
                onx = await submit_codex_organization(
                    client, profile=profile, device_id=device_id,
                    org_id=org_id, project_id=pid, referer_url=next_url,
                    pkce_challenge=code_challenge, state_val=state, log=info,
                )
                code = _pick_code_from_url(onx)
                if code:
                    return code
                code, final_url = await chase_to_localhost_code(
                    client, profile=profile, device_id=device_id, start_url=onx,
                )
                if code:
                    return code
                if final_url and ("/sign-in-with-chatgpt/" in final_url or "consent" in final_url):
                    next2, _orgs2 = await submit_codex_consent(
                        client,
                        profile=profile,
                        device_id=device_id,
                        consent_url=final_url,
                        pkce_challenge=code_challenge,
                        state_val=state,
                        log=info,
                    )
                    if next2:
                        code = _pick_code_from_url(next2)
                        if code:
                            return code
                        code, _ = await chase_to_localhost_code(
                            client, profile=profile, device_id=device_id, start_url=next2,
                        )
                        if code:
                            return code
            else:
                code, final_url = await chase_to_localhost_code(
                    client, profile=profile, device_id=device_id, start_url=next_url,
                )
                if code:
                    return code
                if final_url and ("/sign-in-with-chatgpt/" in final_url or "consent" in final_url):
                    next2, _orgs2 = await submit_codex_consent(
                        client,
                        profile=profile,
                        device_id=device_id,
                        consent_url=final_url,
                        pkce_challenge=code_challenge,
                        state_val=state,
                        log=info,
                    )
                    if next2:
                        code = _pick_code_from_url(next2)
                        if code:
                            return code
                        code, _ = await chase_to_localhost_code(
                            client, profile=profile, device_id=device_id, start_url=next2,
                        )
                        if code:
                            return code
    raise RuntimeError(f"[Codex] 未拿到 localhost code（可能撞 Cloudflare），最后: {target[:120]}")


__all__ = ["AuthentikConfig", "run_openai_sso", "sso_login_to_team", "codex_login_via_sso"]
