"""顶层编排：建子邮箱 → 协议注册 → Cloud Mail 收码 → 产 token。

对外主入口：register_and_auth() —— 一个 async 函数跑完整条链路。
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Optional

from .cloudmail import CloudMailClient, CloudMailConfig
from .core.profile import random_profile
from .flow import RegisterResult, register_via_protocol

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AccountResult:
    """一个注册完成的账号产出。"""

    email: str
    password: str
    access_token: str
    refresh_token: str
    id_token: str
    device_id: str
    duration_seconds: float
    session_token: str = ""
    proxy_used: Optional[str] = None
    # token claims（sub2api 导出用）
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
    # 导出文件路径（开启 export_sub2api 时填）
    sub2api_path: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


async def register_and_auth(
    *,
    cloudmail: CloudMailClient,
    email: Optional[str] = None,
    proxy: Optional[str] = None,
    password: Optional[str] = None,
    otp_max_retries: int = 40,
    otp_poll_interval_s: float = 3.0,
    export_sub2api: bool = True,
    product_dir: str = "product_files",
    fetch_chatgpt_account_id: bool = True,
    chatgpt_web_login: bool = False,
    workspace_id: str = "",
    workspace_join_timeout_s: float = 20.0,
    log: Optional[Callable[[str], None]] = None,
) -> AccountResult:
    """跑完整条链路并返回 token。

    Args:
        cloudmail: 已配置好的 Cloud Mail 客户端
        email: 注册用邮箱；None=自动在 catch-all 域名下新建一个
        proxy: OpenAI 注册走的代理（Cloud Mail 自己的代理在其 config 里）
        password: 注册密码；None=自动生成
        otp_max_retries / otp_poll_interval_s: 收码轮询参数
        export_sub2api: True 时把结果写成 sub2api JSON 文件（<product_dir>/sub2api/<email>.json）
        product_dir: sub2api 文件根目录
        log: 进度回调；None=logger.info
    """
    info = log or (lambda s: logger.info(s))

    # 1) 邮箱：自动新建 or 使用收码后端的默认邮箱 or 用传入的
    if not email:
        info("📧 准备注册邮箱 ...")
        email = await cloudmail.create_account()
        info(f"📧 注册邮箱：{email}")
    else:
        info(f"📧 使用指定邮箱：{email}")

    # 2) 收码器
    otp_fetcher = cloudmail.make_otp_fetcher(
        max_retries=otp_max_retries, poll_interval_s=otp_poll_interval_s,
    )

    # 3) 协议注册（含 token 兑换 + 同 session 内拿 chatgpt_account_id）
    started_all = time.monotonic()
    profile = random_profile()
    workspace_id = (workspace_id or "").strip()

    async def _post_token_web_hook(client, hook_profile, hook_device_id, hook_result) -> None:
        """仍在 auth.openai.com 登录态内，直接接 ChatGPT Web / workspace。"""
        if not (chatgpt_web_login or workspace_id):
            return

        from .chatgpt_web import chatgpt_web_login_with_client, exchange_workspace_access_token
        from .workspace import join_workspace

        info("🌐 [+] 复用注册登录态，切到纯 ChatGPT Web flow 拿 backend-api AT ...")
        hook_result.platform_access_token = hook_result.access_token
        hook_result.platform_refresh_token = hook_result.refresh_token
        hook_result.platform_id_token = hook_result.id_token
        hook_result.platform_expires_in = hook_result.expires_in

        web = await chatgpt_web_login_with_client(
            client,
            email=hook_result.email,
            password=hook_result.password,
            profile=hook_profile,
            device_id=hook_device_id,
            otp_fetcher=otp_fetcher,
            proxy=proxy,
            log=info,
        )
        hook_result.access_token = web.access_token
        hook_result.refresh_token = ""
        hook_result.id_token = web.id_token
        hook_result.session_token = web.session_token
        hook_result.expires_in = web.expires_in
        hook_result.chatgpt_account_id = web.chatgpt_account_id
        hook_result.chatgpt_user_id = web.chatgpt_user_id
        hook_result.plan_type = web.plan_type
        hook_result.sub = web.sub
        hook_result.auth_provider = web.auth_provider
        hook_result.device_id = web.device_id or hook_result.device_id
        hook_result.token_source = "chatgpt_web"
        hook_result.duration_seconds = time.monotonic() - started_all
        info(
            "🌐 [+] Web AT OK · "
            f"account={hook_result.chatgpt_account_id or '(空)'} plan={hook_result.plan_type}"
        )

        if not workspace_id:
            return

        info(f"👥 [+] 加入 workspace：{workspace_id}")
        hook_result.workspace_id = workspace_id
        join_res = join_workspace(
            web.access_token,
            workspace_id,
            timeout=workspace_join_timeout_s,
            did=web.device_id or hook_device_id,
        )
        hook_result.workspace_join_result = join_res
        hook_result.workspace_joined = bool(join_res.get("joined"))
        if not hook_result.workspace_joined:
            raise RuntimeError(
                "workspace 加入失败: "
                f"status={join_res.get('join_status')} error={join_res.get('error')} "
                f"body={str(join_res.get('join_body'))[:300]}"
            )

        info("🔄 [+] workspace 已加入，重新 exchange workspace-scoped AT ...")
        workspace_web = await exchange_workspace_access_token(
            client,
            workspace_id=workspace_id,
            email=hook_result.email,
            profile=hook_profile,
            device_id=web.device_id or hook_device_id,
            proxy=proxy,
            log=info,
        )
        hook_result.access_token = workspace_web.access_token
        hook_result.refresh_token = ""
        hook_result.id_token = workspace_web.id_token
        hook_result.session_token = workspace_web.session_token
        hook_result.expires_in = workspace_web.expires_in
        hook_result.chatgpt_account_id = workspace_web.chatgpt_account_id
        hook_result.chatgpt_user_id = workspace_web.chatgpt_user_id
        hook_result.plan_type = workspace_web.plan_type
        hook_result.sub = workspace_web.sub
        hook_result.auth_provider = workspace_web.auth_provider
        hook_result.token_source = "chatgpt_web_workspace"
        hook_result.device_id = workspace_web.device_id or hook_result.device_id
        hook_result.duration_seconds = time.monotonic() - started_all
        info(
            "✅ [+] workspace-scoped AT OK · "
            f"account={hook_result.chatgpt_account_id or '(空)'} plan={hook_result.plan_type}"
        )

    result: RegisterResult = await register_via_protocol(
        email=email,
        proxy=proxy,
        otp_fetcher=otp_fetcher,
        password=password,
        # 纯 ChatGPT Web 路径不需要也不应该再走 Codex/CLI client 补 account_id。
        fetch_account_id=fetch_chatgpt_account_id and not (chatgpt_web_login or workspace_id),
        profile=profile,
        log=info,
        post_token_hook=_post_token_web_hook if (chatgpt_web_login or workspace_id) else None,
    )

    # 4) 可选：注册后不走 Codex/CLI OAuth，改走纯 ChatGPT Web flow。
    #    这是 chatgpt.com/backend-api 可用的 accessToken；加入 workspace 后必须重新 exchange。
    if chatgpt_web_login and not workspace_id and result.token_source == "platform":
        info("🌐 [+] 注册完成，切到纯 ChatGPT Web flow 拿 backend-api AT ...")
        from .chatgpt_web import chatgpt_web_login_get_tokens

        web = await chatgpt_web_login_get_tokens(
            email=result.email,
            password=result.password,
            proxy=proxy,
            profile=profile,
            device_id=result.device_id,
            otp_fetcher=otp_fetcher,
            log=info,
        )

        result.platform_access_token = result.access_token
        result.platform_refresh_token = result.refresh_token
        result.platform_id_token = result.id_token
        result.platform_expires_in = result.expires_in

        result.access_token = web.access_token
        result.refresh_token = ""
        result.id_token = web.id_token
        result.session_token = web.session_token
        result.expires_in = web.expires_in
        result.chatgpt_account_id = web.chatgpt_account_id
        result.chatgpt_user_id = web.chatgpt_user_id
        result.plan_type = web.plan_type
        result.sub = web.sub
        result.auth_provider = web.auth_provider
        result.token_source = "chatgpt_web"
        result.duration_seconds = time.monotonic() - started_all
        info(
            "🌐 [+] Web AT OK · "
            f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type}"
        )

    if workspace_id and result.token_source != "chatgpt_web_workspace":
        info(f"👥 [+] 加入 workspace：{workspace_id}")
        result.workspace_id = workspace_id
        from .chatgpt_web import (
            chatgpt_web_login_with_client,
            exchange_workspace_access_token,
        )
        from .core.http_client import build_client
        from .workspace import join_workspace

        # join + exchange 必须共用同一个 Web NextAuth session；如果上面已经独立登录过，
        # 这里仍重新登录一遍来保留 httpx cookies，避免只有 AT 没 session 无法 exchange。
        if result.token_source == "platform":
            result.platform_access_token = result.access_token
            result.platform_refresh_token = result.refresh_token
            result.platform_id_token = result.id_token
            result.platform_expires_in = result.expires_in
        async with build_client(profile=profile, proxy=proxy) as web_client:
            web = await chatgpt_web_login_with_client(
                web_client,
                email=result.email,
                password=result.password,
                profile=profile,
                device_id=result.device_id,
                otp_fetcher=otp_fetcher,
                proxy=proxy,
                log=info,
            )
            join_res = join_workspace(
                web.access_token,
                workspace_id,
                timeout=workspace_join_timeout_s,
                did=web.device_id or result.device_id,
            )
            result.workspace_join_result = join_res
            result.workspace_joined = bool(join_res.get("joined"))
            if not result.workspace_joined:
                raise RuntimeError(
                    "workspace 加入失败: "
                    f"status={join_res.get('join_status')} error={join_res.get('error')} "
                    f"body={str(join_res.get('join_body'))[:300]}"
                )

            info("🔄 [+] workspace 已加入，重新 exchange workspace-scoped AT ...")
            workspace_web = await exchange_workspace_access_token(
                web_client,
                workspace_id=workspace_id,
                email=result.email,
                profile=profile,
                device_id=web.device_id or result.device_id,
                proxy=proxy,
                log=info,
            )
            result.access_token = workspace_web.access_token
            result.refresh_token = ""
            result.id_token = workspace_web.id_token
            result.session_token = workspace_web.session_token
            result.expires_in = workspace_web.expires_in
            result.chatgpt_account_id = workspace_web.chatgpt_account_id
            result.chatgpt_user_id = workspace_web.chatgpt_user_id
            result.plan_type = workspace_web.plan_type
            result.sub = workspace_web.sub
            result.auth_provider = workspace_web.auth_provider
            result.token_source = "chatgpt_web_workspace"
            result.device_id = workspace_web.device_id or result.device_id
            result.duration_seconds = time.monotonic() - started_all
            info(
                "✅ [+] workspace-scoped AT OK · "
                f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type}"
            )

    account = AccountResult(
        email=result.email,
        password=result.password,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        id_token=result.id_token,
        session_token=result.session_token,
        device_id=result.device_id,
        duration_seconds=result.duration_seconds,
        proxy_used=result.proxy_used,
        expires_in=result.expires_in,
        chatgpt_account_id=result.chatgpt_account_id,
        chatgpt_user_id=result.chatgpt_user_id,
        plan_type=result.plan_type,
        sub=result.sub,
        auth_provider=result.auth_provider,
        token_source=result.token_source,
        workspace_id=result.workspace_id,
        workspace_joined=result.workspace_joined,
        workspace_join_result=result.workspace_join_result,
    )

    if export_sub2api:
        from .sub2api import export_sub2api_file

        path = export_sub2api_file(result, product_dir=product_dir)
        account.sub2api_path = path
        info(f"📤 sub2api 文件已导出：{path}")

    return account


__all__ = ["AccountResult", "register_and_auth"]
