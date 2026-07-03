"""httpx 包装 + 标准头集合 + W3C/Datadog trace headers。

对应 newgpt2api browser/client.go + jsonHeaders/navHeaders 函数。
"""

from __future__ import annotations

import secrets
import socket
from typing import Any, Optional

import httpx

from .pkce import base64_url, random_bytes
from .profile import Profile

AUTH_BASE = "https://auth.openai.com"
PLATFORM_BASE = "https://platform.openai.com"

# === Platform OAuth client（不强制 add-phone，MVP 用这条）===
PLATFORM_CLIENT_ID = "app_2SKx67EdpoN0G6j64rFvigXD"
PLATFORM_REDIRECT_URI = PLATFORM_BASE + "/auth/callback"
PLATFORM_AUDIENCE = "https://api.openai.com/v1"
PLATFORM_AUTH0_CLIENT = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
DEFAULT_SCOPE = "openid profile email offline_access"


def _hex16() -> str:
    return secrets.token_bytes(8).hex()


def _hex32_dashes_removed() -> str:
    return secrets.token_bytes(16).hex()


def make_trace_headers() -> dict[str, str]:
    """W3C traceparent + Datadog 追踪头。OpenAI 前端 SPA 真实在带。"""
    trace_id = _hex16()
    parent_id = _hex16()
    return {
        "traceparent": f"00-{_hex32_dashes_removed()}-{parent_id}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def json_headers(profile: Profile, device_id: str, referer: str) -> dict[str, str]:
    """application/json POST 用的标准头（不含 sentinel）。"""
    h = {
        "accept": "application/json",
        "content-type": "application/json",
        "accept-language": profile.locale,
        "origin": AUTH_BASE,
        "priority": "u=1, i",
        "referer": referer,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "oai-device-id": device_id,
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        "user-agent": profile.user_agent,
    }
    h.update(make_trace_headers())
    return h


def nav_headers(profile: Profile, device_id: str, *, site: str = "same-origin") -> dict[str, str]:
    """整页跳转类 GET 用的头集合（authorize / email-otp/send / consent 链）。"""
    return {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8",
        "accept-language": profile.locale,
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": site,
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "oai-device-id": device_id,
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        "user-agent": profile.user_agent,
    }


def build_client(
    *,
    profile: Profile,
    proxy: Optional[str],
    timeout_s: float = 60.0,
) -> httpx.AsyncClient:
    """构建支持 OpenAI 注册的 AsyncClient。

    - cookie jar 自动管理
    - proxy 单一 URL（http/https/socks 任意）
    - 默认 follow redirects=True；需要拿 302 Location 时用 follow_redirects=False 单调
    - 一份 UA / Accept-Language 全程一致
    """
    headers = {
        "user-agent": profile.user_agent,
        "accept-language": profile.locale,
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
    }
    # transport 级别重试 —— 处理 ConnectError / RemoteProtocolError /
    # "Server disconnected without sending a response"（代理 keep-alive 断后重连）。
    transport_kwargs: dict[str, Any] = {"retries": 2}
    if proxy:
        transport_kwargs["proxy"] = proxy
    transport = httpx.AsyncHTTPTransport(**transport_kwargs)

    kwargs: dict[str, Any] = {
        "headers": headers,
        "timeout": httpx.Timeout(timeout_s, connect=20.0),
        "follow_redirects": True,
        "http2": False,
        "transport": transport,
        # 只用显式传入的 proxy；不读系统/环境代理，避免行为不可控
        "trust_env": False,
    }
    return httpx.AsyncClient(**kwargs)


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 2,
    backoff_s: float = 1.0,
    **kwargs: Any,
) -> httpx.Response:
    """httpx 请求 + 应用层重试。

    捕获 RemoteProtocolError / ReadError / ConnectError 共 N 次。
    OpenAI / 代理 keep-alive 在 IMAP 长等候后断开是常见的，必须能恢复。
    """
    import asyncio

    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return await client.request(method, url, **kwargs)
        except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError) as exc:
            last_exc = exc
            if attempt >= retries:
                break
            # macOS / 本地 DNS 偶发 Errno 8，立即重试大概率仍失败；先让解析器缓一下。
            msg = str(exc).lower()
            if "nodename nor servname" in msg or "temporary failure in name resolution" in msg:
                try:
                    host = httpx.URL(url).host
                    if host:
                        await asyncio.to_thread(socket.getaddrinfo, host, 443)
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.sleep(backoff_s * (attempt + 1))
    assert last_exc is not None
    raise last_exc


def set_oai_did_cookie(client: httpx.AsyncClient, device_id: str) -> None:
    """OpenAI 通过 `.auth.openai.com` 域的 oai-did cookie 识别"同一会话"，
    sentinel.openai.com 后端会校验。**必须**在第一次 authorize 之前设置。"""
    client.cookies.set("oai-did", device_id, domain="auth.openai.com", path="/")


def clear_oauth_session_cookies(client: httpx.AsyncClient) -> None:
    """清掉 OAuth login flow 的 session cookies（重新走 OAuth 前用）。

    严格对齐 Go `clearOAuthSessionCookies`：注册阶段的 oai-client-auth-session /
    login_session 没有 workspaces[] 字段，必须清掉让 OpenAI 重新种一份带
    workspaces 的 cookie。**保留** oai-did、oai-allow-* 等设备级 cookie。
    """
    names_to_clear = {
        "oai-client-auth-session",
        "login_session",
        "oai-sc",
        "_cfuvid",
        "oai-csrf-cookie",
        "_oai_workspace",
        "oai-allow-organic",
    }
    to_remove: list[tuple[str, str, str]] = []
    for cookie in client.cookies.jar:
        if (cookie.name or "") in names_to_clear:
            to_remove.append((cookie.name, cookie.domain or "", cookie.path or "/"))
    for n, d, p in to_remove:
        try:
            client.cookies.delete(n, domain=d, path=p)
        except Exception:  # noqa: BLE001
            pass
