"""Codex 登录的浏览器渡关模块。

纯协议在 callback/workos 撞 Cloudflare Turnstile 过不去，这里用无头 Chromium
跑完整 Codex OAuth + SAML SSO（浏览器自动解 Cloudflare 挑战、走 Authentik 免密
登录），拦截 localhost:1455/auth/callback?code= 拿到 authorization code，再交回
协议层用 exchange_code_for_token 换 refresh_token / chatgpt_account_id。

Authentik 端是 sso-passthrough flow（无密码，提交 username=email 即登录），所以
浏览器只需在出现用户名输入框时填 email 即可，无需密码。
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse, parse_qs

from .core.pkce import new_pkce, random_state_nonce

logger = logging.getLogger(__name__)

AUTH_BASE = "https://auth.openai.com"
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid profile email offline_access"


@dataclass(slots=True)
class BrowserCodeResult:
    code: str
    code_verifier: str
    final_url: str


def _build_authorize_url(
    *,
    code_challenge: str,
    state: str,
    device_id: str,
    email: str,
    simplified_flow: bool = True,
) -> str:
    params = {
        "response_type": "code",
        "client_id": CODEX_CLIENT_ID,
        "redirect_uri": CODEX_REDIRECT_URI,
        "scope": CODEX_SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "login_hint": email,
    }
    if simplified_flow:
        params["codex_cli_simplified_flow"] = "true"
        params["id_token_add_organizations"] = "true"
    else:
        params["audience"] = "https://api.openai.com/v1"
        params["device_id"] = device_id
        params["prompt"] = "login"
    return f"{AUTH_BASE}/oauth/authorize?{urlencode(params)}"


async def codex_login_browser(
    *,
    email: str,
    device_id: str,
    headless: bool = True,
    proxy: str | None = None,
    timeout_s: float = 90.0,
    chrome_profile: str | None = None,
    simplified_flow: bool = True,
    manual_browser: bool = False,
    log=None,
) -> BrowserCodeResult:
    """用 Chromium 跑完整 Codex SSO，通过本地 callback server 拿 code。

    不使用 Playwright 全局 route 拦截，避免干扰 auth.openai.com 的 Cloudflare
    校验和 consent 页 XHR。
    """
    from playwright.async_api import async_playwright

    info = log or (lambda s: logger.info(s))
    pkce = new_pkce()
    state, _nonce = random_state_nonce()
    auth_url = _build_authorize_url(
        code_challenge=pkce.challenge,
        state=state,
        device_id=device_id,
        email=email,
        simplified_flow=simplified_flow,
    )

    captured: dict[str, str] = {}
    done = asyncio.Event()
    callback_server = await _start_callback_server(captured, done)

    if manual_browser:
        try:
            import webbrowser

            info("🌐 [Manual] 请在真实浏览器完成 SSO / Cloudflare / Codex 授权 ...")
            info(f"🔗 [Manual] {auth_url}")
            webbrowser.open(auth_url)
            try:
                await asyncio.wait_for(done.wait(), timeout=timeout_s)
            except asyncio.TimeoutError:
                pass
        finally:
            callback_server.close()
            await callback_server.wait_closed()

        if not captured.get("code"):
            raise RuntimeError(
                f"[Manual] 未收到 localhost code（超时 {timeout_s}s）；"
                "请确认浏览器最后跳回 http://localhost:1455/auth/callback"
            )
        info(f"✅ [Manual] 拿到 code: {captured['code'][:24]}...")
        return BrowserCodeResult(
            code=captured["code"],
            code_verifier=pkce.verifier,
            final_url=captured.get("final_url", ""),
        )

    try:
        async with async_playwright() as pw:
            launch_kw: dict = {"headless": headless}
            context_kw: dict = {
                "locale": "en-US",
                "viewport": {"width": 1280, "height": 800},
            }
            if proxy:
                launch_kw["proxy"] = {"server": proxy}
            if chrome_profile:
                profile_dir = os.path.expanduser(chrome_profile)
                os.makedirs(profile_dir, exist_ok=True)
                context = await pw.chromium.launch_persistent_context(
                    profile_dir,
                    channel="chrome",
                    **launch_kw,
                    **context_kw,
                )
                browser = None
            else:
                browser = await pw.chromium.launch(**launch_kw)
                context = await browser.new_context(**context_kw)
            page = await context.new_page()

            info("🌐 [Browser] 打开 Codex authorize ...")
            try:
                await page.goto(auth_url, wait_until="commit", timeout=int(timeout_s * 1000))
            except Exception:  # noqa: BLE001
                pass

            # 等待：要么本地 callback server 收到 code，要么需要填 email。
            # Codex SSO 链路上可能出现多个填账号的页面（OpenAI 账号页 +
            # Authentik passthrough 页），按 URL 维度各填一次，避免在同一页反复 fill。
            # Authentik passthrough 会把 username 映射为当前 SSO 邮箱域，
            # 所以这里要填本地账号名，不能把完整邮箱再交给 Authentik 拼一次域名。
            deadline = asyncio.get_event_loop().time() + timeout_s
            filled_on: set[str] = set()
            last_url = ""
            while not done.is_set() and asyncio.get_event_loop().time() < deadline:
                try:
                    cur = page.url
                    key = urlparse(cur).path
                except Exception:  # noqa: BLE001
                    cur, key = "", ""
                if cur and cur != last_url:
                    info(f"➡️  [Browser] 当前页: {cur[:110]}")
                    last_url = cur
                if key not in filled_on:
                    if await _maybe_fill_email(page, _login_value_for_page(cur, email), info):
                        filled_on.add(key)
                await _maybe_click_continue(page, info)
                try:
                    await asyncio.wait_for(done.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

            if not done.is_set():
                # 超时：截图存证，便于定位卡在哪一页
                try:
                    shot = "/tmp/codex_browser_timeout.png"
                    await page.screenshot(path=shot, full_page=True)
                    info(f"📸 [Browser] 超时截图: {shot}（最后页: {last_url[:110]}）")
                except Exception:  # noqa: BLE001
                    pass

            await context.close()
            if browser is not None:
                await browser.close()
    finally:
        callback_server.close()
        await callback_server.wait_closed()

    if not captured.get("code"):
        raise RuntimeError(
            f"[Browser] 未拦到 localhost code（超时 {timeout_s}s）；"
            f"final={captured.get('final_url','')[:120]}"
        )
    info(f"✅ [Browser] 拿到 code: {captured['code'][:24]}...")
    return BrowserCodeResult(
        code=captured["code"],
        code_verifier=pkce.verifier,
        final_url=captured.get("final_url", ""),
    )


async def _start_callback_server(captured: dict[str, str], done: asyncio.Event):
    async def _handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        try:
            data = await reader.read(4096)
            first_line = data.decode("utf-8", "ignore").splitlines()[0] if data else ""
            path = first_line.split(" ", 2)[1] if first_line.startswith("GET ") else ""
            if "/auth/callback" in path:
                parsed = urlparse(path)
                q = parse_qs(parsed.query)
                captured["code"] = (q.get("code") or [""])[0]
                captured["final_url"] = f"{CODEX_REDIRECT_URI}?{parsed.query}"
                done.set()
            body = b"Codex callback captured. You can close this window."
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    try:
        return await asyncio.start_server(_handle_client, "127.0.0.1", 1455)
    except OSError as exc:
        raise RuntimeError("本地 callback 端口 1455 被占用，无法接收 Codex OAuth code") from exc


# 出现 email 输入框（OpenAI 的 /choose-an-account 或 Authentik passthrough）时填入
_EMAIL_SELECTORS = (
    'input[name="email"]',
    'input[type="email"]',
    'input[name="username"]',
    'input[autocomplete="username"]',
    'input[id="username"]',
)
_CONTINUE_SELECTORS = (
    'button[type="submit"]',
    'button:has-text("Continue")',
    'button:has-text("继续")',
    'input[type="submit"]',
)


def _login_value_for_page(url: str, email: str) -> str:
    host = urlparse(url).hostname or ""
    if host.startswith("sso.") and "@" in email:
        return email.split("@", 1)[0]
    return email


async def _maybe_fill_email(page, email: str, info) -> bool:
    """若页面有 email/username 输入框，填入 email。返回是否填过。"""
    for sel in _EMAIL_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() == 0:
                continue
            if not await loc.is_visible(timeout=500):
                continue
            cur = await loc.input_value(timeout=500)
            if cur and "@" in cur:
                continue
            await loc.fill(email, timeout=1500)
            info(f"⌨️  [Browser] 填入 email（{sel}）")
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


async def _maybe_click_continue(page, info) -> None:
    for sel in _CONTINUE_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() == 0:
                continue
            if not await loc.is_visible(timeout=300):
                continue
            if not await loc.is_enabled(timeout=300):
                continue
            await loc.click(timeout=1000)
            return
        except Exception:  # noqa: BLE001
            continue


# -----------------------------------------------------------------------------
# 协议层：用浏览器拿到的 code 换 Codex token
# -----------------------------------------------------------------------------


async def exchange_codex_code(
    client, *, code: str, code_verifier: str,
) -> dict:
    """用 Codex 的 client_id / redirect_uri 兑换 token。

    必须与浏览器 authorize 时用的 client_id / redirect_uri 一致，否则 invalid_grant。
    """
    import urllib.parse

    from .core.http_client import request_with_retry  # 复用带重试的请求

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CODEX_REDIRECT_URI,
        "client_id": CODEX_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/oauth/token",
        content=urllib.parse.urlencode(form),
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        },
    )
    if resp.status_code != 200:
        raise RuntimeError(f"codex oauth/token HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json()


@dataclass(slots=True)
class CodexTokenResult:
    email: str
    access_token: str
    refresh_token: str
    id_token: str
    expires_in: int
    chatgpt_account_id: str
    chatgpt_user_id: str
    plan_type: str
    sub: str


async def codex_get_refresh_token(
    *,
    email: str,
    headless: bool = True,
    proxy: str | None = None,
    timeout_s: float = 90.0,
    chrome_profile: str | None = None,
    simplified_flow: bool = True,
    manual_browser: bool = False,
    log=None,
) -> CodexTokenResult:
    """端到端：浏览器跑 Codex SSO 拿 code → 协议层换 RT / account_id。"""
    from .chatgpt_login import _jwt_claims
    from .core.http_client import build_client
    from .core.pkce import new_device_id
    from .core.profile import random_profile

    info = log or (lambda s: logger.info(s))
    device_id = new_device_id()

    browser_res = await codex_login_browser(
        email=email, device_id=device_id, headless=headless,
        proxy=proxy, timeout_s=timeout_s, chrome_profile=chrome_profile,
        simplified_flow=simplified_flow, manual_browser=manual_browser, log=info,
    )

    profile = random_profile()
    client = build_client(profile=profile, proxy=proxy)
    try:
        tok = await exchange_codex_code(
            client, code=browser_res.code, code_verifier=browser_res.code_verifier,
        )
    finally:
        await client.aclose()

    at = (tok.get("access_token") or "").strip()
    rt = (tok.get("refresh_token") or "").strip()
    idt = (tok.get("id_token") or "").strip()
    if not at:
        raise RuntimeError(f"codex /oauth/token 没返 access_token: {tok}")

    claims = _jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth") or {}
    info(f"✅ [Codex] RT 到手，account_id={auth_info.get('chatgpt_account_id') or '?'}")
    return CodexTokenResult(
        email=email,
        access_token=at,
        refresh_token=rt,
        id_token=idt,
        expires_in=int(tok.get("expires_in") or 0),
        chatgpt_account_id=str(auth_info.get("chatgpt_account_id") or ""),
        chatgpt_user_id=str(auth_info.get("chatgpt_user_id") or ""),
        plan_type=str(auth_info.get("chatgpt_plan_type") or "plus"),
        sub=str(claims.get("sub") or ""),
    )


async def codex_get_refresh_token_via_protocol_sso(
    *,
    email: str,
    proxy: str | None = None,
    timeout_s: float = 90.0,
    sso_connection_id: str,
    sso_base_url: str = "https://sso.example.com",
    join_team_first: bool = False,
    sms_provider=None,
    continue_attempts: int | None = None,
    continue_retry_sleep: float | None = None,
    continue_retry_sleep_max: float | None = None,
    log=None,
) -> CodexTokenResult:
    """纯协议 SAML SSO → Codex code → token，不启动浏览器。"""
    from .chatgpt_login import _jwt_claims
    from .core.http_client import build_client
    from .core.pkce import new_device_id
    from .core.profile import random_profile
    from .sso import AuthentikConfig, codex_login_via_sso, sso_login_to_team

    info = log or (lambda s: logger.info(s))
    pkce = new_pkce()
    state, _nonce = random_state_nonce()

    cfg = AuthentikConfig(
        base_url=sso_base_url,
        connection_id=sso_connection_id,
    )

    profile = random_profile()
    device_id = new_device_id()
    async with build_client(profile=profile, proxy=proxy, timeout_s=timeout_s) as client:
        if join_team_first:
            info("👥 [Protocol SSO] 先进入 ChatGPT team ...")
            await sso_login_to_team(
                client,
                cfg,
                profile=profile,
                device_id=device_id,
                email=email,
                log=info,
            )
        info("🧾 [Codex] 开始 Codex OAuth 授权 ...")
        code = await codex_login_via_sso(
            client,
            cfg,
            profile=profile,
            device_id=device_id,
            email=email,
            code_challenge=pkce.challenge,
            state=state,
            sms_provider=sms_provider,
            continue_attempts=continue_attempts,
            continue_retry_sleep=continue_retry_sleep,
            continue_retry_sleep_max=continue_retry_sleep_max,
            log=info,
        )
        tok = await exchange_codex_code(
            client, code=code, code_verifier=pkce.verifier,
        )

    at = (tok.get("access_token") or "").strip()
    rt = (tok.get("refresh_token") or "").strip()
    idt = (tok.get("id_token") or "").strip()
    if not at:
        raise RuntimeError(f"codex /oauth/token 没返 access_token: {tok}")

    claims = _jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth") or {}
    info(f"✅ [Protocol SSO] RT 到手，account_id={auth_info.get('chatgpt_account_id') or '?'}")
    return CodexTokenResult(
        email=email,
        access_token=at,
        refresh_token=rt,
        id_token=idt,
        expires_in=int(tok.get("expires_in") or 0),
        chatgpt_account_id=str(auth_info.get("chatgpt_account_id") or ""),
        chatgpt_user_id=str(auth_info.get("chatgpt_user_id") or ""),
        plan_type=str(auth_info.get("chatgpt_plan_type") or "plus"),
        sub=str(claims.get("sub") or ""),
    )
