"""Web-controlled Outlook registration batch jobs.

This module is intentionally runtime-stateful: it backs the local FastAPI
console and writes sensitive token outputs to per-job 0700 directories.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import traceback
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Optional

from . import job_store
from .outlook import OutlookOAuthClient, parse_outlook_account_line
from .register import register_and_auth
from .sub2api import upload_product_file

RUN_ROOT = Path(os.environ.get("BATCH_RUN_ROOT") or "/tmp")
MAX_LOG_LINES = int(os.environ.get("BATCH_JOB_MAX_LOG_LINES") or "1200")
PURGE_AFTER_UPLOAD_DEFAULT = os.environ.get("BATCH_PURGE_AFTER_UPLOAD", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

_JOBS: dict[str, dict[str, Any]] = {}
_TASKS: dict[str, asyncio.Task] = {}
_JOBS_LOCK = asyncio.Lock()


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _mask_email(email: str) -> str:
    local, sep, domain = (email or "").partition("@")
    if not sep:
        return email or ""
    return f"{local[:4]}***@{domain}"


def _safe_slug(value: str, *, fallback: str = "job") -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "")).strip("-._")
    return slug[:80] or fallback


def _sanitize_job(job: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in job.items() if k not in {"logs", "_log_seq"}}
    out["logs_tail"] = list(job.get("logs", []))[-80:]
    return out


def _coerce_int(value: Any, default: int, *, lo: int, hi: int) -> int:
    try:
        out = int(value)
    except Exception:  # noqa: BLE001
        out = default
    return max(lo, min(hi, out))


def _coerce_float(value: Any, default: float, *, lo: float, hi: float) -> float:
    try:
        out = float(value)
    except Exception:  # noqa: BLE001
        out = default
    return max(lo, min(hi, out))


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _parse_account_lines(raw: str) -> list[str]:
    lines: list[str] = []
    for line in str(raw or "").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        # Validate here so bad pools fail before starting a background task.
        parse_outlook_account_line(item)
        lines.append(item)
    if not lines:
        raise ValueError("缺少 Outlook 账号行")
    return lines


def _target_email(base_email: str, *, mode: str, alias_prefix: str, slot: int) -> str:
    base_email = base_email.lower().strip()
    if mode == "base":
        return base_email
    local, sep, domain = base_email.partition("@")
    if not sep or not local or not domain:
        return base_email
    prefix = re.sub(r"[^A-Za-z0-9._-]+", "", alias_prefix or "b") or "b"
    if len(prefix) > 10:
        prefix = prefix[:10]
    return f"{local}+{prefix}{slot}@{domain}".lower()


def _artifact_paths(job: dict[str, Any]) -> dict[str, str]:
    out_dir = Path(job["out_dir"])
    artifacts: dict[str, str] = {}
    candidates = {
        "summary": out_dir / "summary.json",
        "results_full": out_dir / "results_full.json",
        "access_tokens": out_dir / "access_tokens_one_per_line.txt",
        "run_log": out_dir / "run.log",
    }
    for product in sorted(out_dir.glob("sub2api_product_*.json")):
        candidates["sub2api_product"] = product
    for receipt in sorted(out_dir.glob("sub2api_upload_receipt_*.json")):
        candidates["sub2api_receipt"] = receipt
    for receipt in sorted(out_dir.glob("sub2api_upload_failed_*.json")):
        candidates["sub2api_failed_receipt"] = receipt
    for name, path in candidates.items():
        if path.exists():
            artifacts[name] = str(path)
    return artifacts


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _append_log(job: dict[str, Any], message: str) -> None:
    if "_log_seq" not in job:
        try:
            job["_log_seq"] = int(job_store.get_logs(str(job["id"]), after=0, limit=0).get("last_seq") or 0)
        except Exception:  # noqa: BLE001
            job["_log_seq"] = 0
    seq = int(job.get("_log_seq") or 0) + 1
    job["_log_seq"] = seq
    ts = time.strftime("%H:%M:%S")
    line = f"{ts} {message}"
    item = {"seq": seq, "ts": ts, "message": message, "line": line}
    job.setdefault("logs", deque(maxlen=MAX_LOG_LINES)).append(item)
    job["updated_at"] = _iso_now()
    log_path = Path(job["out_dir"]) / "run.log"
    with log_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    try:
        job_store.append_log(str(job["id"]), item)
    except Exception:  # noqa: BLE001
        # Logging must never break a registration worker; run.log remains the fallback.
        pass


def _summarize_results(job: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    ok = sum(1 for r in results if r.get("ok"))
    failed = sum(1 for r in results if not r.get("ok"))
    total = int(job.get("total") or 0)
    return {
        "job_id": job["id"],
        "name": job.get("name") or "",
        "status": job.get("status"),
        "target_total": total,
        "ok": ok,
        "failed": failed,
        "pending": max(0, total - len(results)),
        "workspace_id": job.get("workspace_id") or "",
        "email_mode": job.get("email_mode") or "",
        "count_per_account": job.get("count_per_account") or 1,
        "concurrency": job.get("concurrency") or 1,
        "attempts": job.get("attempts") or 1,
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "out_dir": job.get("out_dir"),
        "failures": [
            {
                "mailbox_index": r.get("mailbox_index"),
                "slot": r.get("slot"),
                "email": r.get("email"),
                "error": r.get("error"),
            }
            for r in results
            if not r.get("ok")
        ],
    }


def _persist_state(job: dict[str, Any], results: list[dict[str, Any]]) -> None:
    out_dir = Path(job["out_dir"])
    _write_json(out_dir / "results_full.json", results)
    summary = _summarize_results(job, results)
    _write_json(out_dir / "summary.json", summary)
    job.update({
        "ok": summary["ok"],
        "failed": summary["failed"],
        "pending": summary["pending"],
        "artifacts": _artifact_paths(job),
    })
    try:
        job_store.update_job(job)
        job_store.upsert_results(str(job["id"]), results)
    except Exception:  # noqa: BLE001
        # File artifacts remain authoritative fallback if SQLite is temporarily busy.
        pass


def _build_outputs(job: dict[str, Any], results: list[dict[str, Any]]) -> None:
    out_dir = Path(job["out_dir"])
    rows = sorted(
        [r for r in results if r.get("ok")],
        key=lambda r: (r.get("mailbox_index") or 999999, r.get("slot") or 999999, r.get("email") or ""),
    )
    tokens = [(r.get("access_token") or "").strip() for r in rows if r.get("access_token")]
    at_path = out_dir / "access_tokens_one_per_line.txt"
    at_path.write_text("\n".join(tokens) + ("\n" if tokens else ""), encoding="utf-8")
    os.chmod(at_path, 0o600)

    now = int(time.time())
    accounts: list[dict[str, Any]] = []
    for r in rows:
        expires_in = int(r.get("expires_in") or 0)
        credentials = {
            "access_token": r.get("access_token") or "",
            "chatgpt_account_id": r.get("chatgpt_account_id") or "",
            "chatgpt_user_id": r.get("chatgpt_user_id") or "",
            "expires_at": now + expires_in,
            "expires_in": expires_in,
            "organization_id": "",
            "refresh_token": r.get("refresh_token") or "",
        }
        if r.get("session_token"):
            credentials["session_token"] = r.get("session_token")
        if r.get("workspace_id"):
            credentials["workspace_id"] = r.get("workspace_id")
        extra = {
            "email": r.get("email") or "",
            "sub": r.get("sub") or "",
            "auth_provider": r.get("auth_provider") or "openai",
            "token_source": r.get("token_source") or "",
        }
        if r.get("workspace_id"):
            extra["workspace_id"] = r.get("workspace_id")
            extra["workspace_joined"] = bool(r.get("workspace_joined"))
        accounts.append(
            {
                "name": r.get("email") or "",
                "platform": "openai",
                "type": "oauth",
                "credentials": credentials,
                "extra": extra,
                "concurrency": 10,
                "priority": 1,
                "rate_multiplier": 1,
                "auto_pause_on_expired": True,
                "plan_type": r.get("plan_type") or "plus",
            }
        )
    product = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "proxies": [],
        "accounts": accounts,
    }
    product_path = out_dir / f"sub2api_product_{len(accounts)}.json"
    _write_json(product_path, product)
    job["artifacts"] = _artifact_paths(job)


def _has_uploadable_token(results: list[dict[str, Any]]) -> bool:
    return any(
        bool(r.get("ok") and (r.get("access_token") or r.get("refresh_token") or r.get("session_token")))
        for r in results
    )


def _validate_uploadable_product(product_path: str) -> None:
    try:
        payload = json.loads(Path(product_path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"sub2api product 读取失败: {exc}") from exc
    accounts = payload.get("accounts") if isinstance(payload, dict) else None
    if not isinstance(accounts, list) or not accounts:
        raise RuntimeError("sub2api product 没有可上传账号")
    for account in accounts:
        credentials = account.get("credentials") if isinstance(account, dict) else None
        if not isinstance(credentials, dict) or not (
            credentials.get("access_token")
            or credentials.get("refresh_token")
            or credentials.get("session_token")
        ):
            raise RuntimeError("sub2api product 存在空 token 账号，已拒绝上传")


def _delete_sensitive_artifacts(job: dict[str, Any]) -> list[str]:
    """Delete token-bearing artifacts after a successful upload.

    We keep summary.json, run.log, and upload receipts so the UI still has an
    audit trail, but remove payloads that contain account credentials.
    """
    out_dir = Path(job["out_dir"])
    patterns = [
        "results_full.json",
        "access_tokens_one_per_line.txt",
        "sub2api_product_*.json",
    ]
    deleted: list[str] = []
    for pattern in patterns:
        for path in out_dir.glob(pattern):
            try:
                if path.is_file():
                    path.unlink()
                    deleted.append(path.name)
            except FileNotFoundError:
                continue
    job["artifacts"] = _artifact_paths(job)
    if deleted:
        job["purged_at"] = _iso_now()
        job_store.upsert_artifacts(str(job["id"]), job["artifacts"])
        job_store.update_job(job)
    return deleted


async def _run_one(
    *,
    job: dict[str, Any],
    account_line: str,
    mailbox_index: int,
    slot: int,
    total_slots: int,
    params: dict[str, Any],
) -> dict[str, Any]:
    cfg = parse_outlook_account_line(account_line)
    cfg.alias_mode = "base"
    base_email = cfg.email.lower()
    email = _target_email(
        base_email,
        mode=str(params["email_mode"]),
        alias_prefix=str(params.get("alias_prefix") or "b"),
        slot=slot,
    )
    prefix = f"[mailbox {mailbox_index:02d}/{params['mailbox_count']} slot {slot}/{total_slots} {_mask_email(email)}]"

    def log(message: str) -> None:
        _append_log(job, f"{prefix} {message}")

    last_error = ""
    attempts = int(params["attempts"])
    for attempt in range(1, attempts + 1):
        try:
            log(f"attempt {attempt}/{attempts}")
            client = OutlookOAuthClient(cfg)
            await client.login()
            started = time.monotonic()
            result = await register_and_auth(
                cloudmail=client,
                email=email,
                proxy=params.get("register_proxy") or None,
                otp_max_retries=int(params["otp_max_retries"]),
                otp_poll_interval_s=float(params["otp_poll_interval_s"]),
                export_sub2api=False,
                product_dir=str(Path(job["out_dir"]) / "product_files"),
                fetch_chatgpt_account_id=True,
                chatgpt_web_login=bool(params.get("chatgpt_web") or params.get("workspace_id")),
                workspace_id=str(params.get("workspace_id") or ""),
                workspace_join_timeout_s=float(params["workspace_join_timeout_s"]),
                log=log,
            )
            out = result.to_dict()
            out.update(
                {
                    "ok": True,
                    "mailbox_index": mailbox_index,
                    "slot": slot,
                    "base_email": base_email,
                    "attempt": attempt,
                    "elapsed_seconds": round(time.monotonic() - started, 2),
                }
            )
            log(
                "OK "
                f"email={out.get('email')} workspace_joined={out.get('workspace_joined')} "
                f"plan={out.get('plan_type')} account={out.get('chatgpt_account_id')} "
                f"elapsed={out.get('elapsed_seconds')}s"
            )
            return out
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            log(f"FAIL attempt {attempt}/{attempts}: {last_error}")
            with (Path(job["out_dir"]) / "run.log").open("a", encoding="utf-8") as f:
                f.write(traceback.format_exc(limit=5) + "\n")
            if attempt < attempts:
                await asyncio.sleep(float(params.get("retry_sleep_s") or 8.0))
    return {
        "ok": False,
        "mailbox_index": mailbox_index,
        "slot": slot,
        "email": email,
        "base_email": base_email,
        "error": last_error,
        "workspace_id": params.get("workspace_id") or "",
    }


async def _run_batch_job(job_id: str, account_lines: list[str], params: dict[str, Any]) -> None:
    job = _JOBS[job_id]
    results: list[dict[str, Any]] = []
    result_lock = asyncio.Lock()
    try:
        job["status"] = "running"
        job["started_at"] = _iso_now()
        _append_log(
            job,
            "START "
            f"total={job['total']} mailboxes={len(account_lines)} concurrency={params['concurrency']} "
            f"workspace={params.get('workspace_id') or '-'} mode={params['email_mode']} out={job['out_dir']}",
        )
        _persist_state(job, results)

        async def worker(account_index: int, line: str, slot: int, sem: asyncio.Semaphore) -> None:
            async with sem:
                item = await _run_one(
                    job=job,
                    account_line=line,
                    mailbox_index=account_index,
                    slot=slot,
                    total_slots=int(params["count_per_account"]),
                    params=params,
                )
                async with result_lock:
                    results.append(item)
                    _persist_state(job, results)

        for slot in range(1, int(params["count_per_account"]) + 1):
            job["current_slot"] = slot
            _append_log(job, f"=== slot {slot}/{params['count_per_account']} start ===")
            sem = asyncio.Semaphore(int(params["concurrency"]))
            await asyncio.gather(
                *(worker(idx, line, slot, sem) for idx, line in enumerate(account_lines, 1))
            )
            slot_ok = sum(1 for r in results if r.get("slot") == slot and r.get("ok"))
            _append_log(job, f"=== slot {slot}/{params['count_per_account']} done ok={slot_ok}/{len(account_lines)} ===")

        _build_outputs(job, results)
        _persist_state(job, results)
        if job.get("failed"):
            job["status"] = "completed_with_errors"
        else:
            job["status"] = "completed"
        job["finished_at"] = _iso_now()
        _append_log(job, f"DONE ok={job.get('ok')}/{job.get('total')} failed={job.get('failed')}")
        _persist_state(job, results)

        if params.get("sub2api_upload"):
            try:
                await upload_sub2api_for_job(
                    job_id,
                    base_url=params.get("sub2api_url") or "https://sub2api.example.com",
                    authorization=params.get("sub2api_authorization") or None,
                    admin_api_key=params.get("sub2api_admin_api_key") or None,
                    mode=params.get("sub2api_mode") or "batch",
                )
            except Exception as exc:  # noqa: BLE001
                job["upload_error"] = str(exc)
                _append_log(job, f"sub2api upload failed: {exc}")
    except asyncio.CancelledError:
        job["status"] = "cancelled"
        job["finished_at"] = _iso_now()
        _append_log(job, "CANCELLED")
        _persist_state(job, results)
        raise
    except Exception as exc:  # noqa: BLE001
        job["status"] = "failed"
        job["error"] = str(exc)
        job["finished_at"] = _iso_now()
        _append_log(job, f"FAILED: {exc}")
        with (Path(job["out_dir"]) / "run.log").open("a", encoding="utf-8") as f:
            f.write(traceback.format_exc() + "\n")
        _persist_state(job, results)
    finally:
        job["updated_at"] = _iso_now()
        job["artifacts"] = _artifact_paths(job)
        try:
            job_store.update_job(job)
        finally:
            if job.get("status") not in {"queued", "running", "cancelling"}:
                async with _JOBS_LOCK:
                    _TASKS.pop(job_id, None)
                    _JOBS.pop(job_id, None)


async def initialize_batch_jobs() -> None:
    """Initialize persistent storage and mark orphaned in-flight jobs interrupted."""
    await asyncio.to_thread(job_store.init_db)
    interrupted = await asyncio.to_thread(job_store.mark_interrupted_jobs)
    if interrupted:
        # There is no live asyncio.Task after a process restart, so do not resume.
        pass


def get_control_config() -> dict[str, Any]:
    return job_store.get_config()


def save_control_config(config: dict[str, Any]) -> dict[str, Any]:
    return job_store.save_config(config)


async def create_register_job(params: dict[str, Any]) -> dict[str, Any]:
    account_lines = _parse_account_lines(params.get("outlook_accounts") or "")
    email_mode = str(params.get("email_mode") or "base").strip().lower()
    if email_mode in {"original", "orig", "none"}:
        email_mode = "base"
    if email_mode in {"plus", "alias", "plus_alias"}:
        email_mode = "plus"
    if email_mode not in {"base", "plus"}:
        raise ValueError("email_mode 只支持 base / plus")

    count_per_account = _coerce_int(params.get("count_per_account"), 1, lo=1, hi=20)
    if email_mode == "base" and count_per_account != 1:
        raise ValueError("原始邮箱模式下 count_per_account 必须为 1")

    concurrency = _coerce_int(params.get("concurrency"), 5, lo=1, hi=50)
    attempts = _coerce_int(params.get("attempts"), 2, lo=1, hi=5)
    params = {
        **params,
        "email_mode": email_mode,
        "count_per_account": count_per_account,
        "concurrency": concurrency,
        "attempts": attempts,
        "otp_max_retries": _coerce_int(params.get("otp_max_retries"), 40, lo=1, hi=180),
        "otp_poll_interval_s": _coerce_float(params.get("otp_poll_interval_s"), 3.0, lo=0.5, hi=30.0),
        "workspace_join_timeout_s": _coerce_float(params.get("workspace_join_timeout_s"), 20.0, lo=3.0, hi=180.0),
        "retry_sleep_s": _coerce_float(params.get("retry_sleep_s"), 8.0, lo=0.0, hi=120.0),
        "mailbox_count": len(account_lines),
        "sub2api_mode": params.get("sub2api_mode") if params.get("sub2api_mode") in {"batch", "data"} else "batch",
        "purge_after_upload": _coerce_bool(params.get("purge_after_upload"), PURGE_AFTER_UPLOAD_DEFAULT),
    }

    job_id = uuid.uuid4().hex[:12]
    stamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir = RUN_ROOT / f"gpt_register_lite_ui_{stamp}_{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    now = _iso_now()
    job = {
        "id": job_id,
        "name": str(params.get("name") or f"batch-{stamp}"),
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "workspace_id": str(params.get("workspace_id") or ""),
        "email_mode": email_mode,
        "alias_prefix": str(params.get("alias_prefix") or "b"),
        "count_per_account": count_per_account,
        "mailbox_count": len(account_lines),
        "total": len(account_lines) * count_per_account,
        "ok": 0,
        "failed": 0,
        "pending": len(account_lines) * count_per_account,
        "concurrency": concurrency,
        "attempts": attempts,
        "out_dir": str(out_dir),
        "artifacts": {},
        "purge_after_upload": bool(params.get("purge_after_upload")),
        "logs": deque(maxlen=MAX_LOG_LINES),
        "_log_seq": 0,
    }
    async with _JOBS_LOCK:
        _JOBS[job_id] = job
        await asyncio.to_thread(job_store.create_job, job, params)
        task = asyncio.create_task(_run_batch_job(job_id, account_lines, params))
        _TASKS[job_id] = task
    return _sanitize_job(job)


async def list_jobs() -> list[dict[str, Any]]:
    jobs = await asyncio.to_thread(job_store.list_jobs)
    return sorted([_sanitize_job(job) for job in jobs], key=lambda j: j.get("created_at") or "", reverse=True)


def get_job(job_id: str) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if not job:
        stored = job_store.get_job(job_id)
        if not stored:
            raise KeyError(job_id)
        job = stored
    job["artifacts"] = _artifact_paths(job)
    job_store.upsert_artifacts(job_id, job["artifacts"])
    return _sanitize_job(job)


def get_job_logs(job_id: str, *, after: int = 0) -> dict[str, Any]:
    if not _JOBS.get(job_id) and not job_store.get_job(job_id):
        raise KeyError(job_id)
    return job_store.get_logs(job_id, after=after)


async def cancel_job(job_id: str) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if not job:
        stored = await asyncio.to_thread(job_store.get_job, job_id)
        if not stored:
            raise KeyError(job_id)
        return _sanitize_job(stored)
    task = _TASKS.get(job_id)
    if task and not task.done():
        task.cancel()
        job["status"] = "cancelling"
        _append_log(job, "cancel requested")
        await asyncio.to_thread(job_store.update_job, job)
    return _sanitize_job(job)


async def upload_sub2api_for_job(
    job_id: str,
    *,
    base_url: str,
    authorization: Optional[str] = None,
    admin_api_key: Optional[str] = None,
    mode: str = "batch",
    purge_after_upload: Optional[bool] = None,
) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if not job:
        stored = await asyncio.to_thread(job_store.get_job, job_id)
        if not stored:
            raise KeyError(job_id)
        job = stored
    artifacts = _artifact_paths(job)
    product_path = artifacts.get("sub2api_product")
    if not product_path:
        results_path = Path(job["out_dir"]) / "results_full.json"
        if results_path.exists():
            results = json.loads(results_path.read_text(encoding="utf-8"))
        else:
            results = await asyncio.to_thread(job_store.load_results, job_id)
        if not results:
            raise RuntimeError("还没有可上传的 sub2api product")
        if any(r.get("sensitive_purged") for r in results) and not _has_uploadable_token(results):
            raise RuntimeError("该任务的敏感 token 已在上传后清理，不能重新生成 sub2api product")
        if not _has_uploadable_token(results):
            raise RuntimeError("没有可上传的 token 结果")
        _build_outputs(job, results)
        artifacts = _artifact_paths(job)
        product_path = artifacts.get("sub2api_product")
    if not product_path:
        raise RuntimeError("sub2api product 生成失败")
    _validate_uploadable_product(product_path)
    job["artifacts"] = artifacts
    await asyncio.to_thread(job_store.update_job, job)

    _append_log(job, f"sub2api upload start · file={Path(product_path).name}")
    try:
        result = await upload_product_file(
            product_path,
            base_url=base_url,
            authorization=authorization,
            admin_api_key=admin_api_key,
            mode=mode if mode in {"batch", "data"} else "batch",
            timeout_s=float(os.environ.get("SUB2API_TIMEOUT") or 120),
        )
    except Exception as exc:  # noqa: BLE001
        receipt = Path(product_path).with_name(f"sub2api_upload_failed_{time.strftime('%Y%m%d_%H%M%S')}.json")
        _write_json(
            receipt,
            {
                "uploaded_at": _iso_now(),
                "ok": False,
                "error": str(exc),
                "source_payload": product_path,
                "base_url": base_url,
                "mode": mode,
            },
        )
        job["artifacts"] = _artifact_paths(job)
        await asyncio.to_thread(job_store.update_job, job)
        _append_log(job, f"sub2api upload failed · {exc}")
        raise

    receipt = Path(product_path).with_name(f"sub2api_upload_receipt_{time.strftime('%Y%m%d_%H%M%S')}.json")
    _write_json(
        receipt,
        {"uploaded_at": _iso_now(), "ok": True, **result, "source_payload": product_path},
    )
    job["artifacts"] = _artifact_paths(job)
    job["upload"] = {
        "ok": True,
        "status_code": result.get("status_code"),
        "account_count": result.get("account_count"),
        "receipt": str(receipt),
    }
    _append_log(job, f"sub2api upload ok · accounts={result.get('account_count')} status={result.get('status_code')}")
    await asyncio.to_thread(job_store.update_job, job)
    params = job.get("params") if isinstance(job.get("params"), dict) else {}
    should_purge = _coerce_bool(
        purge_after_upload if purge_after_upload is not None else job.get("purge_after_upload", params.get("purge_after_upload")),
        PURGE_AFTER_UPLOAD_DEFAULT,
    )
    if should_purge:
        await asyncio.to_thread(job_store.purge_sensitive_job_data, job_id)
        deleted = _delete_sensitive_artifacts(job)
        if deleted:
            _append_log(job, "purged sensitive artifacts after upload · " + ", ".join(deleted))
        else:
            _append_log(job, "purged sensitive DB result fields after upload")
        await asyncio.to_thread(job_store.update_job, job)
    return job["upload"]


def get_artifact_path(job_id: str, name: str) -> Path:
    job = _JOBS.get(job_id)
    if not job:
        stored = job_store.get_job(job_id)
        if not stored:
            raise KeyError(job_id)
        job = stored
    artifacts = _artifact_paths(job)
    job_store.upsert_artifacts(job_id, artifacts)
    if name not in artifacts:
        raise KeyError(name)
    path = Path(artifacts[name]).resolve()
    out_dir = Path(job["out_dir"]).resolve()
    if out_dir not in path.parents and path != out_dir:
        raise RuntimeError("artifact path escaped job directory")
    return path
