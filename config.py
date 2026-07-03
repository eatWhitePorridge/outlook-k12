"""配置加载：从 config.json 读，敏感项支持环境变量覆盖。

config.json 示例见 config.example.json。
环境变量（优先级高于文件）：
  CM_BASE_URL / CM_ADMIN_EMAIL / CM_ADMIN_PASSWORD / CM_DOMAIN / CM_PROXY / REGISTER_PROXY
  MAIL_BACKEND=cloudmail|outlook
  OUTLOOK_ACCOUNT_LINE 或 OUTLOOK_EMAIL / OUTLOOK_CLIENT_ID / OUTLOOK_REFRESH_TOKEN
  CHATGPT_WEB_LOGIN=1 / WORKSPACE_ID=...
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from .cloudmail import CloudMailConfig
from .outlook import OutlookOAuthConfig, parse_outlook_account_line


@dataclass(slots=True)
class AppConfig:
    cloudmail: Optional[CloudMailConfig]
    outlook: Optional[OutlookOAuthConfig] = None
    mail_backend: str = "cloudmail"
    register_proxy: Optional[str] = None   # OpenAI 注册走的代理
    otp_max_retries: int = 40
    otp_poll_interval_s: float = 3.0
    export_sub2api: bool = True            # 是否导出 sub2api JSON 文件
    product_dir: str = "product_files"     # sub2api 文件根目录
    fetch_chatgpt_account_id: bool = True  # 注册后补一步 ChatGPT 登录拿 account_id
    chatgpt_web_login: bool = False        # 注册后走纯 ChatGPT Web flow 拿 backend-api AT
    workspace_id: str = ""                 # 非空时 Web AT 加入 workspace 并换 workspace-scoped AT
    workspace_join_timeout_s: float = 20.0


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def load_config(path: Optional[str] = None) -> AppConfig:
    raw: dict = {}
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if content:
            raw = json.loads(content)
    mail_backend = (
        os.environ.get("MAIL_BACKEND")
        or raw.get("mail_backend")
        or raw.get("email_backend")
        or "cloudmail"
    ).strip().lower()
    if mail_backend in {"cloud_mail", "cloud-mail", "cm"}:
        mail_backend = "cloudmail"
    if mail_backend in {"outlook_oauth", "outlook-oauth", "ms", "microsoft", "graph"}:
        mail_backend = "outlook"
    if mail_backend not in {"cloudmail", "outlook"}:
        raise RuntimeError("MAIL_BACKEND 只支持 cloudmail 或 outlook")

    cm = raw.get("cloudmail", {}) if isinstance(raw, dict) else {}
    cloudmail: Optional[CloudMailConfig] = None
    if mail_backend == "cloudmail":
        base_url = os.environ.get("CM_BASE_URL") or cm.get("base_url") or ""
        admin_email = os.environ.get("CM_ADMIN_EMAIL") or cm.get("admin_email") or ""
        admin_password = os.environ.get("CM_ADMIN_PASSWORD") or cm.get("admin_password") or ""
        domain = os.environ.get("CM_DOMAIN") or cm.get("domain") or ""
        cm_proxy = os.environ.get("CM_PROXY") or cm.get("proxy") or None

        if not (base_url and admin_email and admin_password and domain):
            raise RuntimeError(
                "Cloud Mail 配置不完整：需要 base_url / admin_email / admin_password / domain"
                "（见 config.example.json 或用 CM_* 环境变量；或设 MAIL_BACKEND=outlook）"
            )

        cloudmail = CloudMailConfig(
            base_url=base_url,
            admin_email=admin_email,
            admin_password=admin_password,
            domain=domain,
            proxy=cm_proxy,
            token_cache_path=os.environ.get("CM_TOKEN_CACHE_PATH") or cm.get("token_cache_path"),
        )

    outlook_raw = raw.get("outlook", {}) if isinstance(raw, dict) else {}
    outlook: Optional[OutlookOAuthConfig] = None
    if mail_backend == "outlook":
        account_line = (
            os.environ.get("OUTLOOK_ACCOUNT_LINE")
            or outlook_raw.get("account_line")
            or raw.get("outlook_account_line")
            or ""
        ).strip()
        if account_line:
            outlook = parse_outlook_account_line(account_line)
        else:
            email = os.environ.get("OUTLOOK_EMAIL") or outlook_raw.get("email") or ""
            password = os.environ.get("OUTLOOK_PASSWORD") or outlook_raw.get("password") or ""
            client_id = os.environ.get("OUTLOOK_CLIENT_ID") or outlook_raw.get("client_id") or ""
            refresh_token = (
                os.environ.get("OUTLOOK_REFRESH_TOKEN")
                or outlook_raw.get("refresh_token")
                or ""
            )
            if not (email and client_id and refresh_token):
                raise RuntimeError(
                    "Outlook 配置不完整：需要 OUTLOOK_ACCOUNT_LINE，或 "
                    "OUTLOOK_EMAIL / OUTLOOK_CLIENT_ID / OUTLOOK_REFRESH_TOKEN"
                )
            outlook = OutlookOAuthConfig(
                email=email.lower(),
                password=password,
                client_id=client_id,
                refresh_token=refresh_token,
            )
        outlook.tenant = os.environ.get("OUTLOOK_TENANT") or outlook_raw.get("tenant") or outlook.tenant
        outlook.mode = os.environ.get("OUTLOOK_MODE") or outlook_raw.get("mode") or outlook.mode
        outlook.scope = os.environ.get("OUTLOOK_SCOPE") or outlook_raw.get("scope") or outlook.scope
        outlook.imap_scope = (
            os.environ.get("OUTLOOK_IMAP_SCOPE")
            or outlook_raw.get("imap_scope")
            or outlook.imap_scope
        )
        outlook.token_url = os.environ.get("OUTLOOK_TOKEN_URL") or outlook_raw.get("token_url") or outlook.token_url
        outlook.graph_base_url = (
            os.environ.get("OUTLOOK_GRAPH_BASE_URL")
            or outlook_raw.get("graph_base_url")
            or outlook.graph_base_url
        )
        outlook.imap_host = os.environ.get("OUTLOOK_IMAP_HOST") or outlook_raw.get("imap_host") or outlook.imap_host
        outlook.imap_port = int(os.environ.get("OUTLOOK_IMAP_PORT") or outlook_raw.get("imap_port") or outlook.imap_port)
        outlook.client_secret = (
            os.environ.get("OUTLOOK_CLIENT_SECRET")
            or outlook_raw.get("client_secret")
            or outlook.client_secret
        )
        outlook.proxy = os.environ.get("OUTLOOK_PROXY") or outlook_raw.get("proxy") or None
        outlook.alias_mode = (
            os.environ.get("OUTLOOK_ALIAS_MODE")
            or outlook_raw.get("alias_mode")
            or outlook.alias_mode
        )
        outlook.alias_prefix = (
            os.environ.get("OUTLOOK_ALIAS_PREFIX")
            or outlook_raw.get("alias_prefix")
            or outlook.alias_prefix
        )

    register_proxy = os.environ.get("REGISTER_PROXY") or raw.get("register_proxy") or None
    otp_max_retries = int(os.environ.get("OTP_MAX_RETRIES") or raw.get("otp_max_retries", 40))
    otp_poll_interval_s = float(
        os.environ.get("OTP_POLL_INTERVAL_S") or raw.get("otp_poll_interval_s", 3.0)
    )
    # export_sub2api：环境变量 EXPORT_SUB2API=0/false 可关
    env_export = os.environ.get("EXPORT_SUB2API")
    if env_export is not None:
        export_sub2api = env_export.strip().lower() not in ("0", "false", "no", "")
    else:
        export_sub2api = bool(raw.get("export_sub2api", True))
    product_dir = os.environ.get("PRODUCT_DIR") or raw.get("product_dir") or "product_files"
    fetch_chatgpt_account_id = _env_bool(
        "FETCH_CHATGPT_ACCOUNT_ID", bool(raw.get("fetch_chatgpt_account_id", True))
    )
    chatgpt_web_login = _env_bool(
        "CHATGPT_WEB_LOGIN",
        bool(raw.get("chatgpt_web_login", raw.get("use_chatgpt_web", False))),
    )
    workspace_id = (
        os.environ.get("WORKSPACE_ID")
        or os.environ.get("CHATGPT_WORKSPACE_ID")
        or raw.get("workspace_id")
        or raw.get("chatgpt_workspace_id")
        or ""
    ).strip()
    workspace_join_timeout_s = float(
        os.environ.get("WORKSPACE_JOIN_TIMEOUT_S")
        or raw.get("workspace_join_timeout_s", 20.0)
    )
    return AppConfig(
        cloudmail=cloudmail,
        outlook=outlook,
        mail_backend=mail_backend,
        register_proxy=register_proxy,
        otp_max_retries=otp_max_retries,
        otp_poll_interval_s=otp_poll_interval_s,
        export_sub2api=export_sub2api,
        product_dir=product_dir,
        fetch_chatgpt_account_id=fetch_chatgpt_account_id,
        chatgpt_web_login=chatgpt_web_login,
        workspace_id=workspace_id,
        workspace_join_timeout_s=workspace_join_timeout_s,
    )


__all__ = ["AppConfig", "load_config"]
