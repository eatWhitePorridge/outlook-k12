"""sub2api 导出 / 上传。

格式严格对齐 auto/plus_gopay_gptp-plus/oauth_login.js 的 saveIndividualAccountJson：

  {
    "exported_at": "<ISO8601>",
    "proxies": [],
    "accounts": [ { name, platform, type, credentials{...}, extra{...},
                    concurrency, priority, rate_multiplier,
                    auto_pause_on_expired, plan_type } ]
  }

每个账号一个文件：<product_dir>/sub2api/<email>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from typing import TYPE_CHECKING, Any, Literal, Optional

import httpx

if TYPE_CHECKING:
    from .flow import RegisterResult

Sub2APIMode = Literal["batch", "data"]


def build_account_entry(result: "RegisterResult") -> dict[str, Any]:
    """把 RegisterResult 转成 sub2api 的单个 account 条目。"""
    now = int(time.time())
    out = {
        "name": result.email,
        "platform": "openai",
        "type": "oauth",
        "credentials": {
            "access_token": result.access_token,
            "chatgpt_account_id": result.chatgpt_account_id,
            "chatgpt_user_id": result.chatgpt_user_id,
            "expires_at": now + int(result.expires_in or 0),
            "expires_in": int(result.expires_in or 0),
            "organization_id": "",
            "refresh_token": result.refresh_token,
        },
        "extra": {
            "email": result.email,
            "sub": result.sub,
            "auth_provider": getattr(result, "auth_provider", "") or "openai",
            "token_source": getattr(result, "token_source", "") or "platform",
        },
        "concurrency": 10,
        "priority": 1,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
        "plan_type": result.plan_type or "plus",
    }
    session_token = getattr(result, "session_token", "") or ""
    if session_token:
        out["credentials"]["session_token"] = session_token
    workspace_id = getattr(result, "workspace_id", "") or ""
    if workspace_id:
        out["credentials"]["workspace_id"] = workspace_id
        out["extra"]["workspace_id"] = workspace_id
        out["extra"]["workspace_joined"] = bool(getattr(result, "workspace_joined", False))
    return out


def build_sub2api_wrapper(result: "RegisterResult") -> dict[str, Any]:
    """sub2api 文件的完整外层结构（单账号）。"""
    return {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "proxies": [],
        "accounts": [build_account_entry(result)],
    }


def export_sub2api_file(
    result: "RegisterResult",
    *,
    product_dir: str = "product_files",
) -> str:
    """写 <product_dir>/sub2api/<email>.json，返回文件绝对路径。"""
    sub2api_dir = os.path.join(product_dir, "sub2api")
    os.makedirs(sub2api_dir, exist_ok=True)
    path = os.path.join(sub2api_dir, f"{result.email}.json")
    wrapper = build_sub2api_wrapper(result)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wrapper, f, ensure_ascii=False, indent=2)
    return os.path.abspath(path)


def _normalize_base_url(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("缺少 sub2api base URL，请传 --sub2api-url 或设置 SUB2API_BASE_URL")
    return base


def _auth_headers(
    *,
    authorization: str | None = None,
    admin_api_key: str | None = None,
) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    api_key = (admin_api_key or os.environ.get("SUB2API_ADMIN_API_KEY") or "").strip()
    if api_key:
        headers["x-api-key"] = api_key
        return headers

    auth = (
        authorization
        or os.environ.get("SUB2API_AUTHORIZATION")
        or os.environ.get("SUB2API_BEARER_TOKEN")
        or os.environ.get("SUB2API_ADMIN_TOKEN")
        or ""
    ).strip()
    if not auth:
        raise RuntimeError(
            "缺少 sub2api 管理员认证，请传 --sub2api-authorization "
            "或设置 SUB2API_AUTHORIZATION / SUB2API_ADMIN_API_KEY"
        )
    if not auth.lower().startswith("bearer "):
        auth = "Bearer " + auth
    headers["authorization"] = auth
    return headers


def _load_product_payload(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} 不是 JSON object")
    return data


def _coerce_expires_at(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def build_batch_create_payload(product_payload: dict[str, Any]) -> dict[str, Any]:
    """把 product/sub2api JSON 转成 /api/v1/admin/accounts/batch 请求体。"""
    accounts = product_payload.get("accounts")
    if not isinstance(accounts, list) or not accounts:
        raise RuntimeError("product JSON 里没有 accounts[]")

    out: list[dict[str, Any]] = []
    for item in accounts:
        if not isinstance(item, dict):
            continue
        account = {
            "name": item.get("name") or (item.get("extra") or {}).get("email") or "openai-oauth",
            "platform": item.get("platform") or "openai",
            "type": item.get("type") or "oauth",
            "credentials": item.get("credentials") or {},
            "extra": item.get("extra") or {},
            "concurrency": int(item.get("concurrency") or 10),
            "priority": int(item.get("priority") or 1),
            "auto_pause_on_expired": bool(item.get("auto_pause_on_expired", True)),
        }
        if "rate_multiplier" in item:
            account["rate_multiplier"] = item.get("rate_multiplier")
        expires_at = _coerce_expires_at(item.get("expires_at"))
        if expires_at is not None:
            account["expires_at"] = expires_at
        if "group_ids" in item:
            account["group_ids"] = item.get("group_ids") or []
        out.append(account)

    if not out:
        raise RuntimeError("product JSON 里没有可上传的 account")
    return {"accounts": out}


def build_data_import_payload(
    product_payload: dict[str, Any],
    *,
    skip_default_group_bind: bool = True,
) -> dict[str, Any]:
    """把 product/sub2api JSON 包成 /api/v1/admin/accounts/data 请求体。"""
    return {
        "data": {
            "exported_at": product_payload.get("exported_at")
            or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "proxies": product_payload.get("proxies") or [],
            "accounts": product_payload.get("accounts") or [],
        },
        "skip_default_group_bind": skip_default_group_bind,
    }


async def upload_product_payload(
    product_payload: dict[str, Any],
    *,
    base_url: str,
    authorization: str | None = None,
    admin_api_key: str | None = None,
    mode: Sub2APIMode = "batch",
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """上传 product/sub2api JSON 到 sub2api 管理端。"""
    base = _normalize_base_url(base_url)
    headers = _auth_headers(authorization=authorization, admin_api_key=admin_api_key)
    if mode == "batch":
        url = f"{base}/api/v1/admin/accounts/batch"
        payload = build_batch_create_payload(product_payload)
    elif mode == "data":
        url = f"{base}/api/v1/admin/accounts/data"
        payload = build_data_import_payload(product_payload)
    else:
        raise RuntimeError(f"不支持的 sub2api upload mode: {mode}")

    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.post(url, headers=headers, json=payload)
    body_text = resp.text
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {"raw": body_text[:1000]}
    if resp.status_code < 200 or resp.status_code >= 300:
        raise RuntimeError(f"sub2api upload HTTP {resp.status_code}: {body_text[:500]}")
    if isinstance(body, dict) and body.get("success") is False:
        raise RuntimeError(f"sub2api upload failed: {json.dumps(body, ensure_ascii=False)[:800]}")
    return {
        "url": url,
        "mode": mode,
        "status_code": resp.status_code,
        "account_count": len(product_payload.get("accounts") or []),
        "response": body,
    }


async def upload_product_file(
    path: str,
    *,
    base_url: str,
    authorization: str | None = None,
    admin_api_key: str | None = None,
    mode: Sub2APIMode = "batch",
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    return await upload_product_payload(
        _load_product_payload(path),
        base_url=base_url,
        authorization=authorization,
        admin_api_key=admin_api_key,
        mode=mode,
        timeout_s=timeout_s,
    )


def _default_base_url() -> str:
    return os.environ.get("SUB2API_BASE_URL") or "http://127.0.0.1:8080"


async def _main_async(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gpt_register_lite.sub2api")
    sub = parser.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("upload", help="上传 product/sub2api JSON 到 sub2api")
    up.add_argument("json_path")
    up.add_argument("--base-url", default=_default_base_url())
    up.add_argument("--authorization", default=os.environ.get("SUB2API_AUTHORIZATION"))
    up.add_argument("--admin-api-key", default=os.environ.get("SUB2API_ADMIN_API_KEY"))
    up.add_argument("--mode", choices=("batch", "data"), default=os.environ.get("SUB2API_UPLOAD_MODE") or "batch")
    up.add_argument("--timeout", type=float, default=float(os.environ.get("SUB2API_TIMEOUT") or 30))
    args = parser.parse_args(argv)

    if args.cmd == "upload":
        result = await upload_product_file(
            args.json_path,
            base_url=args.base_url,
            authorization=args.authorization,
            admin_api_key=args.admin_api_key,
            mode=args.mode,
            timeout_s=args.timeout,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_main_async(argv))


__all__ = [
    "build_account_entry",
    "build_batch_create_payload",
    "build_data_import_payload",
    "build_sub2api_wrapper",
    "export_sub2api_file",
    "upload_product_file",
    "upload_product_payload",
]


if __name__ == "__main__":
    raise SystemExit(main())
