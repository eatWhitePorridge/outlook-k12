"""gpt_register_lite —— 精简版 OpenAI 协议注册（创建 + auth，无支付）。

收码支持自建 Cloud Mail HTTP API，或 Outlook / Microsoft Graph OAuth。
"""

from .cloudmail import CloudMailClient, CloudMailConfig
from .flow import RegisterResult, register_via_protocol
from .outlook import OutlookOAuthClient, OutlookOAuthConfig
from .register import AccountResult, register_and_auth
from .workspace import join_workspace

__all__ = [
    "CloudMailClient",
    "CloudMailConfig",
    "OutlookOAuthClient",
    "OutlookOAuthConfig",
    "RegisterResult",
    "register_via_protocol",
    "AccountResult",
    "register_and_auth",
    "join_workspace",
    "build_sub2api_wrapper",
    "export_sub2api_file",
]


def __getattr__(name: str):
    if name in {"build_sub2api_wrapper", "export_sub2api_file"}:
        from . import sub2api

        return getattr(sub2api, name)
    raise AttributeError(name)
