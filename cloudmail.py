"""Cloud Mail（example.com）收码客户端。

对接自建的 Cloud Mail（maillab/cloud-mail，部署在 Cloudflare）：
  - 登录拿 JWT（带本地缓存，避免反复登录挤掉网页端会话 —— KV tokens 上限 10）
  - account/add 新建子邮箱（catch-all 域名下的随机地址）
  - 轮询 email/latest 抓 OpenAI 6 位验证码
  - 产出符合 flow.register_via_protocol(otp_fetcher=...) 签名的异步函数

API 约定（核实自源码）：
  - baseURL: <base>/api
  - 认证头: Authorization: <jwt>（无 Bearer 前缀）
  - 响应包装: {code:200, message:'success', data:...}
  - POST /login            body {email,password} -> data.token
  - GET  /account/list     query {size,accountId,lastSort} -> data.list[]（每项含 email/accountId/name）
  - POST /account/add      body {email[,token]} -> data（含 addVerifyOpen）
  - GET  /email/latest     query {emailId,accountId,allReceive} -> data[]（最多 20，倒序）
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import string
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import httpx

logger = logging.getLogger(__name__)

OtpFetcher = Callable[[str], Awaitable[str]]

# OpenAI 验证码：6 位数字。优先从主题/正文里抓。
_OTP_RE = re.compile(r"\b(\d{6})\b")


def _gen_local_part(length: int = 12) -> str:
    """随机邮箱前缀（小写字母+数字，首字符为字母）。"""
    first = secrets.choice(string.ascii_lowercase)
    rest = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length - 1))
    return first + rest


@dataclass(slots=True)
class CloudMailConfig:
    base_url: str                 # 如 https://cloudmail.example.com
    admin_email: str              # 登录用 admin 邮箱
    admin_password: str           # 登录用 admin 密码
    domain: str                   # 子邮箱域名，如 example.com
    proxy: Optional[str] = None   # 访问 Cloud Mail 用的代理（一般直连，留 None）
    token_cache_path: Optional[str] = None  # JWT 缓存文件；None=默认 ~/.gpt_register_lite_cm_token.json
    timeout_s: float = 30.0


class CloudMailClient:
    """Cloud Mail 收码客户端（一个实例复用一个 JWT）。"""

    def __init__(self, cfg: CloudMailConfig):
        self.cfg = cfg
        self._token: str = ""
        self._cache = cfg.token_cache_path or os.path.expanduser(
            "~/.gpt_register_lite_cm_token.json"
        )

    # ------------------------------------------------------------------ token
    def _api(self, path: str) -> str:
        return self.cfg.base_url.rstrip("/") + "/api" + path

    def _load_cached_token(self) -> str:
        try:
            with open(self._cache, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if obj.get("base_url") == self.cfg.base_url and obj.get("admin_email") == self.cfg.admin_email:
                return str(obj.get("token") or "")
        except Exception:  # noqa: BLE001
            pass
        return ""

    def _save_cached_token(self, token: str) -> None:
        try:
            with open(self._cache, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "base_url": self.cfg.base_url,
                        "admin_email": self.cfg.admin_email,
                        "token": token,
                        "saved_at": int(time.time()),
                    },
                    f,
                )
            os.chmod(self._cache, 0o600)
        except Exception:  # noqa: BLE001
            pass

    def _new_client(self) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"timeout": httpx.Timeout(self.cfg.timeout_s, connect=15.0)}
        if self.cfg.proxy:
            kwargs["transport"] = httpx.AsyncHTTPTransport(proxy=self.cfg.proxy, retries=2)
        return httpx.AsyncClient(**kwargs)

    @staticmethod
    def _unwrap(resp: httpx.Response) -> Any:
        """校验 HTTP + Cloud Mail 业务码，返回 data。"""
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:240]}")
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"响应非 JSON: {resp.text[:240]}") from exc
        if body.get("code") != 200:
            raise RuntimeError(f"业务错误 code={body.get('code')} msg={body.get('message')}")
        return body.get("data")

    async def login(self, *, force: bool = False) -> str:
        """拿 JWT。默认优先用缓存；force=True 强制重新登录。"""
        if not force:
            cached = self._token or self._load_cached_token()
            if cached:
                self._token = cached
                return cached
        async with self._new_client() as client:
            resp = await client.post(
                self._api("/login"),
                json={"email": self.cfg.admin_email, "password": self.cfg.admin_password},
            )
            data = self._unwrap(resp)
        token = ""
        if isinstance(data, dict):
            token = str(data.get("token") or "")
        if not token:
            raise RuntimeError("登录成功但响应里没拿到 token")
        self._token = token
        self._save_cached_token(token)
        return token

    async def _auth_get(self, client: httpx.AsyncClient, path: str, params: dict) -> Any:
        """带 token 的 GET；遇 401 自动重登一次。"""
        token = self._token or await self.login()
        resp = await client.get(self._api(path), params=params, headers={"Authorization": token})
        if resp.status_code == 401:
            token = await self.login(force=True)
            resp = await client.get(self._api(path), params=params, headers={"Authorization": token})
        return self._unwrap(resp)

    async def _auth_post(self, client: httpx.AsyncClient, path: str, body: dict) -> Any:
        token = self._token or await self.login()
        resp = await client.post(self._api(path), json=body, headers={"Authorization": token})
        if resp.status_code == 401:
            token = await self.login(force=True)
            resp = await client.post(self._api(path), json=body, headers={"Authorization": token})
        return self._unwrap(resp)

    # --------------------------------------------------------------- account
    async def create_account(self, local_part: Optional[str] = None) -> str:
        """在 catch-all 域名下新建一个子邮箱，返回完整地址。

        若该邮箱新建需要 Turnstile（addVerifyOpen=true），则无法在无人值守下创建，
        会抛错提示改用「我指定地址」或在 Cloud Mail 后台关掉 add 验证。
        """
        local = local_part or _gen_local_part()
        email = f"{local}@{self.cfg.domain}"
        async with self._new_client() as client:
            try:
                data = await self._auth_post(client, "/account/add", {"email": email})
            except RuntimeError as exc:
                raise RuntimeError(f"account/add 失败（{email}）: {exc}") from exc
        if isinstance(data, dict) and data.get("addVerifyOpen"):
            # 后端开了新增验证（Turnstile）；无 token 时后端通常已拒，这里兜底提示
            logger.warning("account/add 返回 addVerifyOpen=true，该实例新增邮箱需人机验证")
        return email

    async def list_accounts(self, size: int = 30) -> list[dict]:
        async with self._new_client() as client:
            data = await self._auth_get(client, "/account/list", {"size": size})
        if isinstance(data, dict):
            lst = data.get("list")
            if isinstance(lst, list):
                return lst
        if isinstance(data, list):
            return data
        return []

    # ----------------------------------------------------------------- 收码
    @staticmethod
    def _extract_otp(mail: dict, exclude: str = "") -> str:
        """从一封邮件里抓 6 位 OTP。优先正文 text，其次 subject，再 content（去标签）。"""
        candidates: list[str] = []
        for field in ("text", "subject", "content"):
            val = mail.get(field)
            if not isinstance(val, str) or not val:
                continue
            stripped = re.sub(r"<[^>]+>", " ", val) if field == "content" else val
            for m in _OTP_RE.findall(stripped):
                if m != exclude:
                    candidates.append(m)
        return candidates[0] if candidates else ""

    async def fetch_openai_otp(
        self,
        email: str,
        *,
        since_email_id: int = 0,
        exclude_code: str = "",
        max_retries: int = 40,
        poll_interval_s: float = 3.0,
        sender_hint: str = "openai",
    ) -> str:
        """轮询 email/latest 抓最新 OpenAI 验证码。

        Args:
            email: 目标子邮箱地址（用于匹配收件人）
            since_email_id: 只看 emailId 大于它的新邮件（增量游标，过滤旧码）
            exclude_code: 排除某个已用过的码
            max_retries / poll_interval_s: 轮询次数与间隔
            sender_hint: 发件人/主题里包含的关键字（小写）
        """
        accounts = await self.list_accounts()
        account_id = 0
        for a in accounts:
            if str(a.get("email", "")).lower() == email.lower():
                account_id = int(a.get("accountId") or 0)
                break

        async with self._new_client() as client:
            for attempt in range(max_retries):
                params: dict[str, Any] = {"emailId": since_email_id}
                if account_id:
                    params["accountId"] = account_id
                else:
                    params["allReceive"] = 1
                try:
                    data = await self._auth_get(client, "/email/latest", params)
                except RuntimeError as exc:
                    logger.warning("email/latest 拉取失败（第 %d 次）: %s", attempt + 1, exc)
                    await asyncio.sleep(poll_interval_s)
                    continue

                mails = data if isinstance(data, list) else (data.get("list") if isinstance(data, dict) else [])
                # 倒序（新→旧），逐封找属于本邮箱、来自 OpenAI 的码
                for mail in (mails or []):
                    to_addr = str(mail.get("toEmail") or mail.get("recipient") or "").lower()
                    sender = str(mail.get("sendEmail") or "").lower()
                    subject = str(mail.get("subject") or "").lower()
                    if account_id == 0 and email.lower() not in to_addr:
                        continue
                    if sender_hint and sender_hint not in sender and sender_hint not in subject:
                        # 不像 OpenAI 的邮件，跳过
                        continue
                    code = self._extract_otp(mail, exclude=exclude_code)
                    if code:
                        return code
                await asyncio.sleep(poll_interval_s)
        raise RuntimeError(f"轮询 {max_retries} 次仍未收到 {email} 的 OpenAI 验证码")

    # ----------------------------------------------------- otp_fetcher 工厂
    def make_otp_fetcher(
        self,
        *,
        max_retries: int = 40,
        poll_interval_s: float = 3.0,
    ) -> OtpFetcher:
        """返回符合 register_via_protocol(otp_fetcher=...) 签名的异步函数。

        每个邮箱独立维护「已见过的码」，避免二次验证时重复取到同一条。
        """
        seen: dict[str, str] = {}

        async def _fetch(email: str) -> str:
            code = await self.fetch_openai_otp(
                email,
                exclude_code=seen.get(email, ""),
                max_retries=max_retries,
                poll_interval_s=poll_interval_s,
            )
            seen[email] = code
            return code

        return _fetch


__all__ = ["CloudMailConfig", "CloudMailClient", "OtpFetcher"]
