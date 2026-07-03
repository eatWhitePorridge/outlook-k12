"""ChatGPT workspace 加入与校验。

这层只负责用 ChatGPT Web accessToken 调 backend-api 主动加入 workspace。
加入后如果要拿 workspace-scoped AT，需要继续复用同一个 NextAuth Web session 调
`chatgpt_web.exchange_workspace_access_token()`。
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Any

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

DEFAULT_BROWSER = "firefox133"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
OAI_CLIENT_VERSION = "prod-497f333866796e100096ad083b51ca949d22e751"
OAI_BUILD_NUMBER = "7646290"

JOIN_ROUTE = "/backend-api/accounts/{account_id}/invites/request"
CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"
CHECK_ROUTE = "/backend-api/accounts/check/{version}"


def normalize_bearer_jwt(token: str) -> str:
    token = (token or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    match = JWT_RE.search(token)
    return match.group(0) if match else token


def decode_jwt_payload(token: str) -> dict[str, Any]:
    token = normalize_bearer_jwt(token)
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("无效的 JWT 格式")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))


def chatgpt_auth_claims(claims: dict[str, Any]) -> dict[str, Any]:
    auth_claim = claims.get("https://api.openai.com/auth", {})
    profile_claim = claims.get("https://api.openai.com/profile", {})
    if not isinstance(auth_claim, dict):
        auth_claim = {}
    if not isinstance(profile_claim, dict):
        profile_claim = {}
    return {
        "chatgpt_account_id": (
            auth_claim.get("chatgpt_account_id")
            or profile_claim.get("account_id")
            or ""
        ),
        "chatgpt_account_user_id": (
            auth_claim.get("chatgpt_account_user_id")
            or auth_claim.get("chatgpt_user_id")
            or auth_claim.get("user_id")
            or claims.get("sub")
            or ""
        ),
        "email": profile_claim.get("email", ""),
    }


def build_authed_headers(
    access_token: str,
    account_id: str,
    did: str,
    session_id: str,
    target_path: str,
    target_route: str,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {normalize_bearer_jwt(access_token)}",
        "chatgpt-account-id": account_id,
        "oai-client-build-number": OAI_BUILD_NUMBER,
        "oai-client-version": OAI_CLIENT_VERSION,
        "oai-device-id": did,
        "oai-language": "zh-CN",
        "oai-session-id": session_id,
        "x-openai-target-path": target_path,
        "x-openai-target-route": target_route,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "Content-Type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }


def _json_or_text(resp: Any, *, limit: int = 800) -> Any:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return str(getattr(resp, "text", "") or "")[:limit]


def _workspace_from_check(check_body: Any, workspace_id: str) -> tuple[bool, dict[str, Any] | None]:
    workspace_item = None
    accounts = check_body.get("accounts", {}) if isinstance(check_body, dict) else {}
    if isinstance(accounts, dict):
        workspace_item = accounts.get(workspace_id)
    elif isinstance(accounts, list):
        for item in accounts:
            if not isinstance(item, dict):
                continue
            acc = item.get("account", item)
            if not isinstance(acc, dict):
                continue
            if acc.get("account_id") == workspace_id or item.get("id") == workspace_id:
                workspace_item = item
                break

    if not isinstance(workspace_item, dict):
        return False, None
    acc = workspace_item.get("account", workspace_item)
    if not isinstance(acc, dict):
        acc = {}
    return True, {
        "account_id": acc.get("account_id") or acc.get("id"),
        "name": acc.get("name"),
        "role": acc.get("account_user_role") or acc.get("role"),
        "plan_type": acc.get("plan_type"),
    }


def join_workspace(
    access_token: str,
    workspace_id: str,
    *,
    browser: str = DEFAULT_BROWSER,
    timeout: float = 20.0,
    did: str = "",
    oai_session_id: str = "",
) -> dict[str, Any]:
    """用当前个人账号 Web AT 请求加入目标 workspace，并用 accounts/check 校验。"""
    try:
        from curl_cffi import requests
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("缺少 curl_cffi，请先 pip install curl_cffi") from exc

    token = normalize_bearer_jwt(access_token)
    claims = decode_jwt_payload(token)
    auth_info = chatgpt_auth_claims(claims)
    member_account_id = str(auth_info["chatgpt_account_id"] or "")
    email = str(auth_info["email"] or "")
    workspace_id = (workspace_id or "").strip()

    if not member_account_id:
        return {
            "email": email,
            "member_account_id": "",
            "target_workspace_id": workspace_id,
            "joined": False,
            "error": "Token 中未找到 chatgpt_account_id，请确认传入的是 ChatGPT Web accessToken",
        }
    if not workspace_id:
        return {
            "email": email,
            "member_account_id": member_account_id,
            "target_workspace_id": "",
            "joined": False,
            "error": "workspace_id 为空",
        }

    session = requests.Session(impersonate=browser)
    did = did or str(uuid.uuid4())
    session_id = oai_session_id or str(uuid.uuid4())
    join_path = JOIN_ROUTE.format(account_id=workspace_id)

    try:
        join_resp = session.post(
            f"https://chatgpt.com{join_path}",
            headers=build_authed_headers(
                token, member_account_id, did, session_id, join_path, JOIN_ROUTE
            ),
            data="{}",
            timeout=timeout,
        )
        join_status = int(join_resp.status_code)
        join_body = _json_or_text(join_resp)
    except Exception as exc:  # noqa: BLE001
        return {
            "email": email,
            "member_account_id": member_account_id,
            "target_workspace_id": workspace_id,
            "joined": False,
            "error": f"加入请求失败: {type(exc).__name__}: {exc}",
        }

    try:
        check_resp = session.get(
            f"https://chatgpt.com{CHECK_PATH}",
            headers=build_authed_headers(
                token, member_account_id, did, session_id, CHECK_PATH, CHECK_ROUTE
            ),
            timeout=timeout,
        )
        check_status = int(check_resp.status_code)
        check_body = _json_or_text(check_resp)
    except Exception as exc:  # noqa: BLE001
        return {
            "email": email,
            "member_account_id": member_account_id,
            "target_workspace_id": workspace_id,
            "join_status": join_status,
            "join_body": join_body,
            "joined": False,
            "error": f"验证状态失败: {type(exc).__name__}: {exc}",
        }

    joined, workspace_summary = _workspace_from_check(check_body, workspace_id)
    return {
        "email": email,
        "member_account_id": member_account_id,
        "target_workspace_id": workspace_id,
        "join_status": join_status,
        "join_body": join_body,
        "check_status": check_status,
        "joined": joined,
        "workspace": workspace_summary,
        "error": "" if joined else "accounts/check 未找到目标 workspace",
    }


__all__ = [
    "CHECK_PATH",
    "CHECK_ROUTE",
    "JOIN_ROUTE",
    "chatgpt_auth_claims",
    "decode_jwt_payload",
    "join_workspace",
    "normalize_bearer_jwt",
]
