"""Outlook / Microsoft Graph OAuth 收码客户端。

支持常见邮箱池格式：

    email----password----client_id----refresh_token

实现方式：
  1. 用 refresh_token 调 Microsoft identity platform `/oauth2/v2.0/token`
     换 Microsoft Graph access_token；
  2. 调 `GET /me/messages` 拉最近邮件；
  3. 从 OpenAI / ChatGPT 验证邮件主题、预览、正文中提取 6 位 OTP。

该模块暴露的 `OutlookOAuthClient` 与 `CloudMailClient` 保持同样的最小接口：
`login()`、`create_account()`、`make_otp_fetcher()`，因此可直接接入
`register_and_auth()`。
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import email
import email.policy
import imaplib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

OtpFetcher = Callable[[str], Awaitable[str]]

_OTP_RE = re.compile(r"\b(\d{6})\b")
_OPENAI_BRAND_RE = re.compile(r"openai|chatgpt", re.I)
_OPENAI_SENDER_RE = re.compile(
    r"(@|\.)openai\.com$|(@|\.)tm\.openai\.com$|(@|\.)openai-mail\.com$",
    re.I,
)

DEFAULT_GRAPH_SCOPE = "https://graph.microsoft.com/.default offline_access"
FALLBACK_GRAPH_SCOPE = "https://graph.microsoft.com/.default offline_access"
DEFAULT_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
DEFAULT_IMAP_SCOPE = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"
DEFAULT_IMAP_HOST = "outlook.office365.com"
DEFAULT_IMAP_PORT = 993
FALLBACK_TENANTS = ("common", "consumers", "organizations")


@dataclass(slots=True)
class OutlookOAuthConfig:
    email: str
    client_id: str
    refresh_token: str
    password: str = ""
    tenant: str = "common"
    mode: str = "auto"  # auto|graph|imap
    scope: str = DEFAULT_GRAPH_SCOPE
    imap_scope: str = DEFAULT_IMAP_SCOPE
    graph_base_url: str = DEFAULT_GRAPH_BASE_URL
    imap_host: str = DEFAULT_IMAP_HOST
    imap_port: int = DEFAULT_IMAP_PORT
    token_url: str = ""
    client_secret: str = ""
    proxy: Optional[str] = None
    timeout_s: float = 30.0
    alias_mode: str = "plus"  # plus|base|none
    alias_prefix: str = "oai"


def parse_outlook_account_line(line: str) -> OutlookOAuthConfig:
    """解析 `email----password----client_id----refresh_token`。

    refresh_token 里如果意外包含分隔符，也会通过 `join` 保留下来。
    """
    raw = (line or "").strip()
    if not raw:
        raise ValueError("Outlook account line 为空")

    if "----" not in raw:
        raise ValueError("Outlook account line 需要是 email----password----client_id----refresh_token 格式")

    parts = [p.strip() for p in raw.split("----")]
    if len(parts) < 4:
        raise ValueError("Outlook account line 字段不足，需要 email/password/client_id/refresh_token")

    email = parts[0].lower()
    password = parts[1]
    client_id = parts[2]
    refresh_token = "----".join(parts[3:]).strip()

    if "@" not in email:
        raise ValueError("Outlook 邮箱格式非法")
    if not client_id:
        raise ValueError("Outlook client_id 为空")
    if not refresh_token:
        raise ValueError("Outlook refresh_token 为空")

    return OutlookOAuthConfig(
        email=email,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
    )


def _snippet(text: str, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:limit]


def _mail_addr(value: Any) -> str:
    """兼容 Graph message 的 from/sender/emailAddress 结构。"""
    if not isinstance(value, dict):
        return ""
    ea = value.get("emailAddress")
    if isinstance(ea, dict):
        return str(ea.get("address") or ea.get("name") or "")
    return ""


def _normalize_addr(addr: str) -> str:
    return str(addr or "").strip().lower()


def _message_recipients(message: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("toRecipients", "ccRecipients", "bccRecipients"):
        vals = message.get(key)
        if not isinstance(vals, list):
            continue
        for item in vals:
            if not isinstance(item, dict):
                continue
            addr = _mail_addr(item)
            if addr:
                out.append(_normalize_addr(addr))
    return out


def _message_ts(message: dict[str, Any]) -> float:
    raw = str(message.get("receivedDateTime") or "").strip()
    if not raw:
        return 0.0
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:  # noqa: BLE001
        return 0.0


def _recipient_matches(message: dict[str, Any], target_email: str) -> bool:
    """Graph 消息必须匹配本次注册邮箱，避免抓到同邮箱其它 alias 的旧 OTP。"""
    target = _normalize_addr(target_email)
    if not target:
        return True
    recipients = _message_recipients(message)
    if not recipients:
        # 有些 Graph 响应可能没返回收件人；这种情况下不硬拦，交给正文匹配兜底。
        return True
    return target in recipients


def _body_text(message: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("subject", "bodyPreview"):
        val = message.get(key)
        if isinstance(val, str):
            parts.append(val)
    body = message.get("body")
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, str):
            # Graph 默认 HTML；即使指定 Prefer=text，也兜底去标签。
            content = re.sub(r"<[^>]+>", " ", content)
            parts.append(content)
    return "\n".join(parts)


def _looks_like_openai_message(message: dict[str, Any]) -> bool:
    subject = str(message.get("subject") or "")
    preview = str(message.get("bodyPreview") or "")
    sender = _mail_addr(message.get("from")) or _mail_addr(message.get("sender"))
    sender_addr = sender.lower().strip()
    if _OPENAI_SENDER_RE.search(sender_addr):
        return True
    return bool(_OPENAI_BRAND_RE.search(f"{subject}\n{preview}\n{sender_addr}"))


def _is_excluded_code(code: str, exclude: Any = "") -> bool:
    if not code:
        return True
    if isinstance(exclude, (set, list, tuple)):
        return code in {str(x) for x in exclude if x}
    return bool(exclude) and code == str(exclude)


def _extract_otp(message: dict[str, Any], *, exclude: Any = "") -> str:
    if not _looks_like_openai_message(message):
        return ""
    for code in _OTP_RE.findall(_body_text(message)):
        if not _is_excluded_code(code, exclude):
            return code
    return ""


def _xoauth2_sasl_str(email_addr: str, access_token: str) -> bytes:
    return f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01".encode()


def _email_text(msg: EmailMessage) -> str:
    parts: list[str] = []
    if msg.get("subject"):
        parts.append(str(msg.get("subject") or ""))
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype not in {"text/plain", "text/html"}:
                continue
            try:
                content = part.get_content()
            except Exception:  # noqa: BLE001
                continue
            if isinstance(content, str):
                if ctype == "text/html":
                    content = re.sub(r"<[^>]+>", " ", content)
                parts.append(content)
    else:
        try:
            content = msg.get_content()
        except Exception:  # noqa: BLE001
            content = ""
        if isinstance(content, str):
            if msg.get_content_type() == "text/html":
                content = re.sub(r"<[^>]+>", " ", content)
            parts.append(content)
    return "\n".join(parts)


def _is_openai_email(msg: EmailMessage) -> bool:
    subject = str(msg.get("subject") or "")
    sender = parseaddr(str(msg.get("from") or ""))[1].lower()
    if _OPENAI_SENDER_RE.search(sender):
        return True
    haystack = f"{subject}\n{sender}\n{_email_text(msg)[:1000]}"
    return bool(_OPENAI_BRAND_RE.search(haystack))


def _extract_otp_from_email(msg: EmailMessage, *, exclude: Any = "") -> str:
    if not _is_openai_email(msg):
        return ""
    for code in _OTP_RE.findall(_email_text(msg)):
        if not _is_excluded_code(code, exclude):
            return code
    return ""


def _parse_folder_name(raw_line: bytes | str) -> str:
    line = raw_line.decode(errors="ignore") if isinstance(raw_line, bytes) else str(raw_line)
    # 常见格式：(<flags>) "/" "Inbox"；简单取最后一段 quoted string。
    quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
    if quoted:
        return quoted[-1].replace(r"\"", '"')
    parts = line.rsplit(" ", 1)
    return parts[-1].strip().strip('"') if parts else ""


def _is_junk_folder(raw_line: bytes | str, folder_name: str) -> bool:
    line = raw_line.decode(errors="ignore") if isinstance(raw_line, bytes) else str(raw_line)
    low = f"{line}\n{folder_name}".lower()
    return "\\junk" in low or "junk" in low or "spam" in low or "垃圾" in low


class OutlookOAuthClient:
    """Outlook OAuth / Graph 收码客户端。"""

    def __init__(self, cfg: OutlookOAuthConfig):
        self.cfg = cfg
        self._access_tokens: dict[str, tuple[str, float]] = {}
        self._refresh_token = cfg.refresh_token
        self._mail_mode = (cfg.mode or "auto").strip().lower()

    def _new_client(self) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"timeout": httpx.Timeout(self.cfg.timeout_s, connect=15.0)}
        if self.cfg.proxy:
            kwargs["transport"] = httpx.AsyncHTTPTransport(proxy=self.cfg.proxy, retries=2)
        return httpx.AsyncClient(**kwargs)

    def _token_endpoint(self, tenant: str = "") -> str:
        if self.cfg.token_url:
            return self.cfg.token_url
        tenant = (tenant or self.cfg.tenant or "common").strip().strip("/") or "common"
        return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    async def _oauth_token(self, *, scope: str, force: bool = False) -> str:
        """用 refresh_token 换指定 scope 的 access_token。"""
        now = time.time()
        cached = self._access_tokens.get(scope)
        if not force and cached and now < cached[1] - 60:
            return cached[0]

        data = {
            "client_id": self.cfg.client_id,
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        }
        if scope:
            data["scope"] = scope
        if self.cfg.client_secret:
            data["client_secret"] = self.cfg.client_secret

        tenant_candidates: list[str]
        if self.cfg.token_url:
            tenant_candidates = [self.cfg.tenant or "common"]
        else:
            first = (self.cfg.tenant or "common").strip() or "common"
            tenant_candidates = [first, *(t for t in FALLBACK_TENANTS if t != first)]

        last_err = ""
        async with self._new_client() as client:
            for tenant in tenant_candidates:
                resp = await client.post(
                    self._token_endpoint(tenant),
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp.status_code == 200:
                    break
                try:
                    body = resp.json()
                    err = body.get("error_description") or body.get("error") or body
                except Exception:  # noqa: BLE001
                    err = resp.text
                last_err = f"tenant={tenant} HTTP {resp.status_code}: {_snippet(err)}"
                # tenant 不匹配时继续；scope/凭据真错也先让 fallback tenant 试完，便于个人号兼容。
            else:
                raise RuntimeError(f"Outlook OAuth token 刷新失败: {last_err}")

        body = resp.json()
        token = str(body.get("access_token") or "")
        if not token:
            raise RuntimeError(f"Outlook OAuth token 响应缺 access_token: {_snippet(resp.text)}")

        expires_in = int(body.get("expires_in") or 3600)
        self._access_tokens[scope] = (token, time.time() + max(60, expires_in))

        # Microsoft 可能返回新的 refresh_token；运行期替换，避免后续轮询继续用旧 token。
        new_rt = str(body.get("refresh_token") or "")
        if new_rt:
            self._refresh_token = new_rt
            self.cfg.refresh_token = new_rt
            # refresh token 轮换后，清掉其他 scope 的旧 access token 缓存。
            self._access_tokens = {scope: self._access_tokens[scope]}

        return token

    async def login(self, *, force: bool = False) -> str:
        """预登录。

        mode=auto 时先试 Graph `Mail.Read`；若 refresh_token 未授权该 scope，
        自动回退到 Outlook IMAP XOAUTH2 scope。与 CloudMailClient.login() 保持同名。
        """
        mode = (self.cfg.mode or self._mail_mode or "auto").strip().lower()
        if mode not in {"auto", "graph", "imap"}:
            raise RuntimeError("Outlook mode 只支持 auto / graph / imap")
        if mode in {"graph", "auto"}:
            graph_scopes = [
                self.cfg.scope,
                *([FALLBACK_GRAPH_SCOPE] if self.cfg.scope != FALLBACK_GRAPH_SCOPE else []),
            ]
            last_graph_error: Exception | None = None
            for scope in graph_scopes:
                if not scope:
                    continue
                try:
                    token = await self._oauth_token(scope=scope, force=force)
                    self.cfg.scope = scope
                    self._mail_mode = "graph"
                    return token
                except Exception as exc:  # noqa: BLE001
                    last_graph_error = exc
                    logger.info("Graph scope 不可用（%s）：%s", scope, exc)
            try:
                raise last_graph_error or RuntimeError("Graph scope 不可用")
            except Exception:
                if mode == "graph":
                    raise
                logger.info("Graph Mail.Read scope 不可用，自动回退 IMAP XOAUTH2")
        token = await self._oauth_token(scope=self.cfg.imap_scope, force=force)
        self._mail_mode = "imap"
        return token

    async def create_account(self, local_part: Optional[str] = None) -> str:
        """Outlook 后端用 plus addressing 生成变体邮箱。

        不会真的调用 Microsoft 创建账号；返回 `base+tag@outlook.com` 这类可收信
        alias。若 `alias_mode=base|none`，则保持旧行为，直接返回配置邮箱。
        """
        mode = (self.cfg.alias_mode or "plus").strip().lower()
        if mode in {"", "base", "none", "off", "false", "0"}:
            return self.cfg.email

        local, sep, domain = self.cfg.email.partition("@")
        if not sep or not local or not domain:
            return self.cfg.email

        tag = (local_part or "").strip()
        if not tag:
            # Outlook.com 的 plus addressing 对很长 tag 不稳定；之前
            # prefix + 13 位毫秒时间戳 + 5 位随机数会生成 20+ 字符的 tag，
            # 实测 OpenAI 发码会卡在收信阶段。这里改成短 tag（通常 7~12 位），
            # 既保留足够随机性，也避免长 alias 不投递。
            prefix = re.sub(r"[^A-Za-z0-9._-]+", "", self.cfg.alias_prefix or "oai") or "oai"
            suffix = secrets.token_hex(2)
            if len(prefix) > 10:
                prefix = prefix[:10]
            tag = f"{prefix}{suffix}"
        tag = re.sub(r"[^A-Za-z0-9._-]+", "", tag)
        if not tag:
            tag = f"oai{secrets.randbelow(1000000):06d}"
        return f"{local}+{tag}@{domain}".lower()

    async def _graph_get(
        self,
        client: httpx.AsyncClient,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        prefer_text_body: bool = False,
    ) -> dict[str, Any]:
        token = await self._oauth_token(scope=self.cfg.scope)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if prefer_text_body:
            headers["Prefer"] = 'outlook.body-content-type="text"'

        url = self.cfg.graph_base_url.rstrip("/") + path
        resp = await client.get(url, params=params, headers=headers)
        if resp.status_code == 401:
            token = await self._oauth_token(scope=self.cfg.scope, force=True)
            headers["Authorization"] = f"Bearer {token}"
            resp = await client.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            try:
                body = resp.json()
                err = body.get("error", {}).get("message") or body
            except Exception:  # noqa: BLE001
                err = resp.text
            raise RuntimeError(f"Graph GET {path} HTTP {resp.status_code}: {_snippet(err)}")

        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Graph GET {path} 响应非 JSON: {_snippet(resp.text)}") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Graph GET {path} 响应结构异常: {_snippet(resp.text)}")
        return data

    def _imap_scan_once_sync(self, *, exclude_code: Any = "", include_junk: bool = True) -> str:
        token = self._access_tokens.get(self.cfg.imap_scope, ("", 0.0))[0]
        if not token:
            raise RuntimeError("IMAP access_token 为空")
        client: imaplib.IMAP4_SSL | None = None
        try:
            client = imaplib.IMAP4_SSL(
                self.cfg.imap_host,
                int(self.cfg.imap_port),
                timeout=self.cfg.timeout_s,
            )
            client.authenticate("XOAUTH2", lambda _: _xoauth2_sasl_str(self.cfg.email, token))
            status, folders_raw = client.list()
            if status != "OK" or not folders_raw:
                folders_raw = []
            inbox = "INBOX"
            junk_folders: list[str] = []
            for raw in folders_raw:
                if not raw:
                    continue
                folder = _parse_folder_name(raw)
                if not folder:
                    continue
                if folder.lower() == "inbox":
                    inbox = folder
                if include_junk and _is_junk_folder(raw, folder):
                    junk_folders.append(folder)
            targets = [inbox, *junk_folders]
            seen_folders: set[str] = set()
            for folder in targets:
                if not folder or folder in seen_folders:
                    continue
                seen_folders.add(folder)
                try:
                    status, _ = client.select(f'"{folder}"', readonly=True)
                    if status != "OK":
                        status, _ = client.select(folder, readonly=True)
                    if status != "OK":
                        continue
                    status, data = client.search(None, "ALL")
                    if status != "OK" or not data or not data[0]:
                        continue
                    ids = data[0].split()
                    # UID/序号通常递增；只看最新 30 封。
                    for msg_id in reversed(ids[-30:]):
                        status, fetched = client.fetch(msg_id, "(RFC822)")
                        if status != "OK" or not fetched:
                            continue
                        raw_msg = b""
                        for item in fetched:
                            if isinstance(item, tuple) and item[1]:
                                raw_msg = item[1]
                                break
                        if not raw_msg:
                            continue
                        msg = email.message_from_bytes(raw_msg, policy=email.policy.default)
                        code = _extract_otp_from_email(msg, exclude=exclude_code)
                        if code:
                            return code
                except imaplib.IMAP4.error as exc:
                    logger.warning("扫描 Outlook 文件夹 %s 失败: %s", folder, exc)
                    continue
            return ""
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    client.logout()
                except Exception:  # noqa: BLE001
                    pass

    async def _fetch_message_body(
        self,
        client: httpx.AsyncClient,
        message_id: str,
    ) -> dict[str, Any]:
        mid = quote(message_id, safe="")
        return await self._graph_get(
            client,
            f"/me/messages/{mid}",
            params={
                "$select": "id,subject,from,sender,receivedDateTime,body,bodyPreview,toRecipients",
            },
            prefer_text_body=True,
        )

    async def fetch_openai_otp(
        self,
        email: str,
        *,
        exclude_code: Any = "",
        since_ts: float = 0.0,
        max_retries: int = 40,
        poll_interval_s: float = 3.0,
    ) -> str:
        """轮询 Outlook 收件箱，返回 OpenAI 6 位验证码。"""
        target = (email or self.cfg.email).strip().lower()
        if target != self.cfg.email.lower():
            logger.warning("Outlook 后端配置邮箱为 %s，但请求收码邮箱为 %s", self.cfg.email, target)

        if self._mail_mode != "graph":
            return await self._fetch_openai_otp_imap(
                email,
                exclude_code=exclude_code,
                max_retries=max_retries,
                poll_interval_s=poll_interval_s,
            )

        params = {
            "$top": "25",
            "$orderby": "receivedDateTime desc",
            "$select": "id,subject,from,sender,receivedDateTime,bodyPreview,toRecipients",
        }

        async with self._new_client() as client:
            for attempt in range(max_retries):
                try:
                    data = await self._graph_get(client, "/me/messages", params=params)
                    messages = data.get("value") if isinstance(data, dict) else []
                    if not isinstance(messages, list):
                        messages = []

                    for msg in messages:
                        if not isinstance(msg, dict):
                            continue
                        if since_ts and _message_ts(msg) and _message_ts(msg) < since_ts:
                            continue

                        if not _recipient_matches(msg, target):
                            continue

                        code = _extract_otp(msg, exclude=exclude_code)
                        if code:
                            return code

                        # bodyPreview 不一定包含验证码；只对疑似 OpenAI 邮件再补抓正文。
                        if _looks_like_openai_message(msg) and msg.get("id"):
                            try:
                                full_msg = await self._fetch_message_body(client, str(msg["id"]))
                            except Exception as exc:  # noqa: BLE001
                                logger.warning("Graph 拉取邮件正文失败: %s", exc)
                                continue
                            if not _recipient_matches(full_msg, target):
                                continue
                            code = _extract_otp(full_msg, exclude=exclude_code)
                            if code:
                                return code

                except Exception as exc:  # noqa: BLE001
                    logger.warning("Outlook Graph 拉取失败（第 %d 次）: %s", attempt + 1, exc)

                await asyncio.sleep(poll_interval_s)

        raise RuntimeError(f"轮询 {max_retries} 次仍未收到 {target} 的 OpenAI 验证码")

    async def _fetch_openai_otp_imap(
        self,
        email: str,
        *,
        exclude_code: Any = "",
        max_retries: int = 40,
        poll_interval_s: float = 3.0,
    ) -> str:
        target = (email or self.cfg.email).strip().lower()
        if target != self.cfg.email.lower():
            logger.warning("Outlook 后端配置邮箱为 %s，但请求收码邮箱为 %s", self.cfg.email, target)

        await self._oauth_token(scope=self.cfg.imap_scope)
        for attempt in range(max_retries):
            try:
                code = await asyncio.to_thread(
                    self._imap_scan_once_sync,
                    exclude_code=exclude_code,
                    include_junk=True,
                )
                if code:
                    return code
            except imaplib.IMAP4.error as exc:
                logger.warning("Outlook IMAP 认证/扫描失败（第 %d 次），强刷 token: %s", attempt + 1, exc)
                await self._oauth_token(scope=self.cfg.imap_scope, force=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Outlook IMAP 拉取失败（第 %d 次）: %s", attempt + 1, exc)
            await asyncio.sleep(poll_interval_s)

        raise RuntimeError(f"轮询 {max_retries} 次仍未收到 {target} 的 OpenAI 验证码")

    def make_otp_fetcher(
        self,
        *,
        max_retries: int = 40,
        poll_interval_s: float = 3.0,
    ) -> OtpFetcher:
        """返回符合 register_via_protocol(otp_fetcher=...) 签名的异步函数。"""
        # 不能只按 code 去重：ChatGPT passwordless/choose-account 有时会重发同一个
        # 6 位码。用“本次 fetch 之后的新邮件时间”隔离旧邮件，同时允许新邮件复用同码。
        since_by_email: dict[str, float] = {}
        started_at = time.time() - 10

        async def _fetch(email: str) -> str:
            since_ts = since_by_email.get(email, started_at)
            code = await self.fetch_openai_otp(
                email,
                exclude_code="",
                since_ts=since_ts,
                max_retries=max_retries,
                poll_interval_s=poll_interval_s,
            )
            since_by_email[email] = time.time()
            return code

        return _fetch


__all__ = [
    "DEFAULT_GRAPH_SCOPE",
    "FALLBACK_GRAPH_SCOPE",
    "DEFAULT_IMAP_SCOPE",
    "OutlookOAuthConfig",
    "OutlookOAuthClient",
    "OtpFetcher",
    "parse_outlook_account_line",
]
