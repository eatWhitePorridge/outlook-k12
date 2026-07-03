"""最小 HTTP 服务：POST 触发注册，返回 token。

启动：
  uvicorn gpt_register_lite.api:app --host 127.0.0.1 --port 8000
  （或 python -m gpt_register_lite.api）

接口：
  POST /register       body {email?, password?, proxy?}  -> 注册一个，返回 token
  POST /codex/sso      body {email, upload?}             -> SSO 拿 Codex RT，可自动上传 sub2api
  GET  /healthz                                          -> 健康检查

鉴权：可选。设了环境变量 API_KEY 时，请求需带 header  X-API-Key: <key>。
注意：该服务会触发对外注册行为，务必只绑 127.0.0.1 或加 API_KEY，别裸奔公网。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

import httpx

try:
    from fastapi import FastAPI, Header, HTTPException, Query
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, Field
except ImportError as exc:  # noqa: BLE001
    raise RuntimeError(
        "HTTP 服务需要 fastapi + uvicorn，请先 pip install fastapi uvicorn"
    ) from exc

from .config import load_config
from .cloudmail import CloudMailClient
from .outlook import OutlookOAuthClient
from .register import register_and_auth
from .sso_browser import CODEX_CLIENT_ID, codex_get_refresh_token_via_protocol_sso
from .sub2api import upload_product_payload
from .test_codex_browser import _build_product_json
from .batch_jobs import (
    cancel_job,
    create_register_job,
    get_artifact_path,
    get_control_config,
    get_job,
    get_job_logs,
    initialize_batch_jobs,
    list_jobs,
    save_control_config,
    upload_sub2api_for_job,
)

_CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.json")
_API_KEY = os.environ.get("API_KEY", "")
_DEFAULT_SSO_CONNECTION_ID = "conn_xxxxxxxxxxxxxxxxxxxxxxxxxx"
_DEFAULT_SSO_BASE_URL = "https://sso.example.com"
_DEFAULT_SSO_EMAIL_DOMAIN = "example.com"

app = FastAPI(title="gpt_register_lite", version="1.0")

_cfg = None
_client = None


@app.on_event("startup")
async def _startup() -> None:
    await initialize_batch_jobs()


def _ensure_client():
    global _cfg, _client
    if _client is None:
        _cfg = load_config(_CONFIG_PATH)
        if _cfg.mail_backend == "outlook":
            if _cfg.outlook is None:
                raise RuntimeError("mail_backend=outlook 但缺少 outlook 配置")
            _client = OutlookOAuthClient(_cfg.outlook)
        else:
            if _cfg.cloudmail is None:
                raise RuntimeError("mail_backend=cloudmail 但缺少 cloudmail 配置")
            _client = CloudMailClient(_cfg.cloudmail)
    return _client


class RegisterReq(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    proxy: Optional[str] = None
    chatgpt_web: Optional[bool] = None
    workspace_id: Optional[str] = None


class CodexSSOReq(BaseModel):
    email: str
    proxy: Optional[str] = None
    proxy_provider_url: Optional[str] = None
    sso_connection_id: Optional[str] = None
    sso_base_url: Optional[str] = None
    sso_email_domain: Optional[str] = None
    join_team_first: Optional[bool] = None
    timeout: float = 120.0
    retries: int = 2
    continue_attempts: Optional[int] = None
    continue_retry_sleep: Optional[float] = None
    continue_retry_sleep_max: Optional[float] = None
    upload: Optional[bool] = None
    save_local: Optional[bool] = None
    save_dir: Optional[str] = None
    include_payload: bool = False
    sub2api_url: Optional[str] = None
    sub2api_authorization: Optional[str] = None
    sub2api_admin_api_key: Optional[str] = None
    sub2api_mode: str = "batch"


class BatchRegisterReq(BaseModel):
    name: Optional[str] = None
    outlook_accounts: str = Field(..., description="每行 email----password----client_id----refresh_token")
    workspace_id: str = ""
    count_per_account: int = 1
    email_mode: str = "base"  # base|plus
    alias_prefix: str = "b"
    concurrency: int = 5
    attempts: int = 2
    register_proxy: Optional[str] = None
    otp_max_retries: int = 40
    otp_poll_interval_s: float = 3.0
    workspace_join_timeout_s: float = 20.0
    retry_sleep_s: float = 8.0
    chatgpt_web: bool = True
    sub2api_upload: bool = False
    sub2api_url: str = "https://sub2api.example.com"
    sub2api_authorization: Optional[str] = None
    sub2api_admin_api_key: Optional[str] = None
    sub2api_mode: str = "batch"
    purge_after_upload: bool = True


class Sub2APIUploadReq(BaseModel):
    sub2api_url: str = "https://sub2api.example.com"
    sub2api_authorization: Optional[str] = None
    sub2api_admin_api_key: Optional[str] = None
    sub2api_mode: str = "batch"
    purge_after_upload: Optional[bool] = None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _setting(name: str, default: str, override: Optional[str] = None) -> str:
    value = override if override is not None else os.environ.get(name)
    value = (value or "").strip()
    return value or default


def _sso_email(raw_email: str, *, domain: str) -> str:
    email = raw_email.strip()
    if "@" in email:
        return email
    domain = domain.strip().lstrip("@") or _DEFAULT_SSO_EMAIL_DOMAIN
    return f"{email}@{domain}"


def _attempt_sso_email(raw_email: str, *, domain: str, attempt: int) -> str:
    return _sso_email(raw_email.strip(), domain=domain)


def _check_key(x_api_key: Optional[str]) -> None:
    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")


async def _fetch_dynamic_proxy(provider_url: str, *, timeout_s: float = 25.0) -> str:
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.get(provider_url)
    if resp.status_code != 200:
        raise RuntimeError(f"proxy provider HTTP {resp.status_code}: {resp.text[:200]}")
    for line in resp.text.replace("\r", "\n").splitlines():
        proxy = line.strip()
        if not proxy:
            continue
        if not proxy.startswith(("http://", "https://")):
            proxy = "http://" + proxy
        return proxy
    raise RuntimeError("proxy provider returned empty response")


def _save_sanitized_codex_file(res, *, save_dir: str) -> str:
    """Save a sub2api-importable account file without explicit email fields."""
    account_id = res.chatgpt_account_id or "unknown-account"
    now = int(time.time())
    stamp = time.time_ns()
    expires_in = int(res.expires_in or 0)
    expires_at = now + expires_in if expires_in > 0 else None
    expires_at_iso = (
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
        if expires_at
        else None
    )
    account = {
        "name": f"openai-{account_id}",
        "platform": "openai",
        "type": "oauth",
        "expires_at": expires_at,
        "auto_pause_on_expired": True,
        "concurrency": 10,
        "priority": 1,
        "credentials": {
            "access_token": res.access_token,
            "refresh_token": res.refresh_token,
            "client_id": CODEX_CLIENT_ID,
            "chatgpt_account_id": res.chatgpt_account_id,
            "chatgpt_user_id": res.chatgpt_user_id,
            "expires_at": expires_at_iso,
            "expires_in": expires_in,
            "plan_type": res.plan_type,
        },
        "extra": {
            "auth_provider": "openai",
            "source": "codex_sso",
        },
    }
    if account["expires_at"] is None:
        account.pop("expires_at")
    if account["credentials"]["expires_at"] is None:
        account["credentials"].pop("expires_at")
    payload = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "proxies": [],
        "accounts": [account],
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if "@" in text or "email" in text.lower():
        raise RuntimeError("sanitized payload still contains email-like content")

    os.makedirs(save_dir, exist_ok=True)
    safe_id = "".join(ch for ch in account_id if ch.isalnum() or ch in "-_") or "unknown"
    path = os.path.join(save_dir, f"{stamp}_{safe_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
        f.write("\n")
    return os.path.abspath(path)


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


_STATIC_DIR = Path(__file__).resolve().parent / "static"

if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


def _control_page() -> FileResponse:
    return FileResponse(str(_STATIC_DIR / "control.html"), media_type="text/html")


@app.get("/")
async def index() -> FileResponse:
    return _control_page()


@app.get("/ui")
async def ui() -> FileResponse:
    return _control_page()


@app.get("/batch/config")
async def batch_get_config(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict[str, Any]:
    _check_key(x_api_key)
    return get_control_config()


@app.put("/batch/config")
async def batch_save_config(
    payload: dict[str, Any],
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict[str, Any]:
    _check_key(x_api_key)
    return save_control_config(payload)


@app.post("/batch/register-jobs")
async def batch_register_jobs(
    req: BatchRegisterReq,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    try:
        payload = req.model_dump() if hasattr(req, "model_dump") else req.dict()
        return await create_register_job(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/batch/register-jobs")
async def batch_list_jobs(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> list[dict]:
    _check_key(x_api_key)
    return await list_jobs()


@app.get("/batch/register-jobs/{job_id}")
async def batch_get_job(
    job_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    try:
        return get_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc


@app.get("/batch/register-jobs/{job_id}/logs")
async def batch_get_logs(
    job_id: str,
    after: int = Query(default=0, ge=0),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    try:
        return get_job_logs(job_id, after=after)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc


@app.post("/batch/register-jobs/{job_id}/cancel")
async def batch_cancel_job(
    job_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    try:
        return await cancel_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc


@app.post("/batch/register-jobs/{job_id}/upload-sub2api")
async def batch_upload_sub2api(
    job_id: str,
    req: Sub2APIUploadReq,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    try:
        return await upload_sub2api_for_job(
            job_id,
            base_url=req.sub2api_url,
            authorization=req.sub2api_authorization,
            admin_api_key=req.sub2api_admin_api_key,
            mode=req.sub2api_mode,
            purge_after_upload=req.purge_after_upload,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="job not found") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/batch/register-jobs/{job_id}/artifacts/{artifact_name}")
async def batch_download_artifact(
    job_id: str,
    artifact_name: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> FileResponse:
    _check_key(x_api_key)
    try:
        path = get_artifact_path(job_id, artifact_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="artifact not found") from exc
    return FileResponse(str(path), filename=path.name)


@app.post("/register")
async def register(
    req: RegisterReq,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    client = _ensure_client()
    cfg = _cfg
    try:
        result = await register_and_auth(
            cloudmail=client,
            email=req.email,
            password=req.password,
            proxy=req.proxy or cfg.register_proxy,
            otp_max_retries=cfg.otp_max_retries,
            otp_poll_interval_s=cfg.otp_poll_interval_s,
            export_sub2api=cfg.export_sub2api,
            product_dir=cfg.product_dir,
            fetch_chatgpt_account_id=cfg.fetch_chatgpt_account_id,
            chatgpt_web_login=(
                req.chatgpt_web if req.chatgpt_web is not None else cfg.chatgpt_web_login
            ),
            workspace_id=(req.workspace_id or cfg.workspace_id),
            workspace_join_timeout_s=cfg.workspace_join_timeout_s,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"ok": True, **result.to_dict()}


@app.post("/codex/sso")
async def codex_sso(
    req: CodexSSOReq,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> dict:
    _check_key(x_api_key)
    sso_email_domain = _setting(
        "SSO_EMAIL_DOMAIN", _DEFAULT_SSO_EMAIL_DOMAIN, req.sso_email_domain,
    )
    sso_connection_id = _setting(
        "SSO_CONNECTION_ID", _DEFAULT_SSO_CONNECTION_ID, req.sso_connection_id,
    )
    sso_base_url = _setting("SSO_BASE_URL", _DEFAULT_SSO_BASE_URL, req.sso_base_url)
    join_team_first = (
        req.join_team_first
        if req.join_team_first is not None
        else _env_bool("CODEX_SSO_JOIN_TEAM_FIRST", False)
    )
    retries = max(1, min(int(req.retries or 1), 5))
    errors: list[str] = []
    if req.proxy_provider_url is None:
        proxy_provider_url = (os.environ.get("CODEX_SSO_PROXY_PROVIDER_URL") or "").strip()
    else:
        proxy_provider_url = req.proxy_provider_url.strip()
    proxy = req.proxy
    proxy_source = "request" if proxy else "none"

    res = None
    for _attempt in range(1, retries + 1):
        email = _attempt_sso_email(req.email, domain=sso_email_domain, attempt=_attempt)
        try:
            if not req.proxy and proxy_provider_url:
                proxy = await _fetch_dynamic_proxy(
                    proxy_provider_url,
                    timeout_s=float(os.environ.get("CODEX_SSO_PROXY_PROVIDER_TIMEOUT") or 25),
                )
                proxy_source = "provider"
            extra_kwargs = {}
            if req.continue_attempts is not None:
                extra_kwargs["continue_attempts"] = req.continue_attempts
            if req.continue_retry_sleep is not None:
                extra_kwargs["continue_retry_sleep"] = req.continue_retry_sleep
            if req.continue_retry_sleep_max is not None:
                extra_kwargs["continue_retry_sleep_max"] = req.continue_retry_sleep_max
            res = await codex_get_refresh_token_via_protocol_sso(
                email=email,
                proxy=proxy,
                timeout_s=req.timeout,
                sso_connection_id=sso_connection_id,
                sso_base_url=sso_base_url,
                join_team_first=join_team_first,
                **extra_kwargs,
            )
            break
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
    if res is None:
        raise HTTPException(status_code=500, detail={"message": "codex sso failed", "errors": errors})

    product = _build_product_json(res)
    should_upload = req.upload
    if should_upload is None:
        should_upload = _env_bool("CODEX_SSO_DEFAULT_UPLOAD", True)
    should_save = req.save_local
    if should_save is None:
        should_save = _env_bool("CODEX_SSO_DEFAULT_SAVE_LOCAL", False)

    saved_path = None
    if should_save:
        try:
            saved_path = _save_sanitized_codex_file(
                res,
                save_dir=req.save_dir or os.environ.get("CODEX_SSO_SAVE_DIR") or "/data/saved_accounts",
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"local save failed: {exc}") from exc

    upload_result = None
    if should_upload:
        try:
            upload_result = await upload_product_payload(
                product,
                base_url=req.sub2api_url
                or os.environ.get("SUB2API_BASE_URL")
                or "https://sub2api.example.com",
                authorization=req.sub2api_authorization
                or os.environ.get("SUB2API_AUTHORIZATION"),
                admin_api_key=req.sub2api_admin_api_key
                or os.environ.get("SUB2API_ADMIN_API_KEY"),
                mode=req.sub2api_mode if req.sub2api_mode in ("batch", "data") else "batch",
                timeout_s=float(os.environ.get("SUB2API_TIMEOUT") or 60),
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"sub2api upload failed: {exc}") from exc

    out = {
        "ok": True,
        "chatgpt_account_id": res.chatgpt_account_id,
        "chatgpt_user_id": res.chatgpt_user_id,
        "plan_type": res.plan_type,
        "refresh_token": f"{res.refresh_token[:24]}...{res.refresh_token[-12:]}",
        "saved_path": saved_path,
        "proxy_source": proxy_source,
        "upload": upload_result,
        "attempt_errors": errors,
    }
    if not _env_bool("CODEX_SSO_HIDE_EMAIL_IN_RESPONSE", False):
        out["email"] = res.email
    if req.include_payload:
        out["product_json"] = product
    return out


def main() -> None:
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
