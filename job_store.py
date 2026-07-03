"""SQLite persistence for the web batch registration console.

The batch runner still keeps the currently-running asyncio.Task in memory, but
job metadata, logs, result rows, artifacts, upload receipts, and UI preferences
live here so a Docker/container restart does not wipe the console state.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

RUN_ROOT = Path(os.environ.get("BATCH_RUN_ROOT") or "/tmp")
DB_PATH = Path(os.environ.get("REGISTER_DB_PATH") or str(RUN_ROOT / "register_console.db"))

_LOCK = threading.RLock()
_CONN: sqlite3.Connection | None = None
_INIT_DONE = False

_RUNNING_STATUSES = ("queued", "running", "cancelling")
_SENSITIVE_RESULT_KEYS = {
    "access_token",
    "refresh_token",
    "session_token",
    "id_token",
    "token",
    "authorization",
    "password",
}
_SENSITIVE_PARAM_KEYS = {
    "outlook_accounts",
    "sub2api_authorization",
    "sub2api_admin_api_key",
}


def _chmod_db_files() -> None:
    for path in (DB_PATH, Path(str(DB_PATH) + "-wal"), Path(str(DB_PATH) + "-shm")):
        try:
            os.chmod(path, 0o600)
        except FileNotFoundError:
            pass
        except PermissionError:
            pass


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return default


def _redact_params(params: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(params or {})
    for key in _SENSITIVE_PARAM_KEYS:
        if out.get(key):
            if key == "outlook_accounts":
                out[key] = f"<redacted {len(str(out[key]).splitlines())} lines>"
            else:
                out[key] = "<redacted>"
    return out


def _sanitize_result_payload(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload or {})
    for key in list(out.keys()):
        if key in _SENSITIVE_RESULT_KEYS or key.endswith("_token"):
            out.pop(key, None)
    if "credentials" in out and isinstance(out["credentials"], dict):
        creds = dict(out["credentials"])
        for key in list(creds.keys()):
            if key in _SENSITIVE_RESULT_KEYS or key.endswith("_token"):
                creds.pop(key, None)
        out["credentials"] = creds
    out["sensitive_purged"] = True
    return out


def connect() -> sqlite3.Connection:
    global _CONN
    if _CONN is not None:
        return _CONN
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONN = sqlite3.connect(
        str(DB_PATH),
        timeout=30,
        isolation_level=None,
        check_same_thread=False,
    )
    _CONN.row_factory = sqlite3.Row
    _CONN.execute("PRAGMA journal_mode=WAL")
    _CONN.execute("PRAGMA synchronous=NORMAL")
    _CONN.execute("PRAGMA busy_timeout=30000")
    _chmod_db_files()
    return _CONN


def init_db() -> None:
    global _INIT_DONE
    if _INIT_DONE:
        return
    with _LOCK:
        if _INIT_DONE:
            return
        conn = connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              started_at TEXT,
              finished_at TEXT,
              workspace_id TEXT NOT NULL DEFAULT '',
              email_mode TEXT NOT NULL DEFAULT '',
              alias_prefix TEXT NOT NULL DEFAULT '',
              count_per_account INTEGER NOT NULL DEFAULT 1,
              mailbox_count INTEGER NOT NULL DEFAULT 0,
              total INTEGER NOT NULL DEFAULT 0,
              ok INTEGER NOT NULL DEFAULT 0,
              failed INTEGER NOT NULL DEFAULT 0,
              pending INTEGER NOT NULL DEFAULT 0,
              concurrency INTEGER NOT NULL DEFAULT 1,
              attempts INTEGER NOT NULL DEFAULT 1,
              out_dir TEXT NOT NULL DEFAULT '',
              current_slot INTEGER,
              error TEXT,
              upload_json TEXT,
              params_json TEXT,
              artifacts_json TEXT,
              purged_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

            CREATE TABLE IF NOT EXISTS job_logs (
              job_id TEXT NOT NULL,
              seq INTEGER NOT NULL,
              ts TEXT NOT NULL,
              message TEXT NOT NULL,
              line TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY (job_id, seq)
            );

            CREATE TABLE IF NOT EXISTS job_results (
              job_id TEXT NOT NULL,
              mailbox_index INTEGER NOT NULL,
              slot INTEGER NOT NULL,
              email TEXT NOT NULL DEFAULT '',
              base_email TEXT NOT NULL DEFAULT '',
              ok INTEGER NOT NULL DEFAULT 0,
              plan_type TEXT NOT NULL DEFAULT '',
              workspace_joined INTEGER NOT NULL DEFAULT 0,
              chatgpt_account_id TEXT NOT NULL DEFAULT '',
              elapsed_seconds REAL,
              error TEXT,
              result_json TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (job_id, mailbox_index, slot)
            );

            CREATE INDEX IF NOT EXISTS idx_job_results_job_id ON job_results(job_id);

            CREATE TABLE IF NOT EXISTS job_artifacts (
              job_id TEXT NOT NULL,
              name TEXT NOT NULL,
              path TEXT NOT NULL,
              created_at TEXT NOT NULL,
              PRIMARY KEY (job_id, name)
            );

            CREATE TABLE IF NOT EXISTS app_config (
              key TEXT PRIMARY KEY,
              value_json TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            """
        )
        _ensure_columns(conn)
        _chmod_db_files()
        _INIT_DONE = True


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """Tiny migration helper for DB files created by older local builds."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    desired = {
        "upload_json": "TEXT",
        "params_json": "TEXT",
        "artifacts_json": "TEXT",
        "purged_at": "TEXT",
        "current_slot": "INTEGER",
        "error": "TEXT",
    }
    for name, sql_type in desired.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} {sql_type}")


def _job_columns(job: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
    artifacts = job.get("artifacts") or {}
    return {
        "id": job.get("id") or "",
        "name": job.get("name") or "",
        "status": job.get("status") or "queued",
        "created_at": job.get("created_at") or iso_now(),
        "updated_at": job.get("updated_at") or iso_now(),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "workspace_id": job.get("workspace_id") or "",
        "email_mode": job.get("email_mode") or "",
        "alias_prefix": job.get("alias_prefix") or "",
        "count_per_account": int(job.get("count_per_account") or 1),
        "mailbox_count": int(job.get("mailbox_count") or 0),
        "total": int(job.get("total") or 0),
        "ok": int(job.get("ok") or 0),
        "failed": int(job.get("failed") or 0),
        "pending": int(job.get("pending") or 0),
        "concurrency": int(job.get("concurrency") or 1),
        "attempts": int(job.get("attempts") or 1),
        "out_dir": job.get("out_dir") or "",
        "current_slot": job.get("current_slot"),
        "error": job.get("error") or job.get("upload_error"),
        "upload_json": _json_dumps(job.get("upload") or {}) if job.get("upload") else None,
        "params_json": _json_dumps(_redact_params(params)) if params is not None else None,
        "artifacts_json": _json_dumps(artifacts),
        "purged_at": job.get("purged_at"),
    }


def create_job(job: dict[str, Any], params: dict[str, Any] | None = None) -> None:
    init_db()
    data = _job_columns(job, params)
    with _LOCK:
        connect().execute(
            """
            INSERT INTO jobs (
              id,name,status,created_at,updated_at,started_at,finished_at,workspace_id,email_mode,alias_prefix,
              count_per_account,mailbox_count,total,ok,failed,pending,concurrency,attempts,out_dir,current_slot,
              error,upload_json,params_json,artifacts_json,purged_at
            ) VALUES (
              :id,:name,:status,:created_at,:updated_at,:started_at,:finished_at,:workspace_id,:email_mode,:alias_prefix,
              :count_per_account,:mailbox_count,:total,:ok,:failed,:pending,:concurrency,:attempts,:out_dir,:current_slot,
              :error,:upload_json,:params_json,:artifacts_json,:purged_at
            )
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name,status=excluded.status,updated_at=excluded.updated_at,started_at=excluded.started_at,
              finished_at=excluded.finished_at,workspace_id=excluded.workspace_id,email_mode=excluded.email_mode,
              alias_prefix=excluded.alias_prefix,count_per_account=excluded.count_per_account,
              mailbox_count=excluded.mailbox_count,total=excluded.total,ok=excluded.ok,failed=excluded.failed,
              pending=excluded.pending,concurrency=excluded.concurrency,attempts=excluded.attempts,out_dir=excluded.out_dir,
              current_slot=excluded.current_slot,error=excluded.error,upload_json=excluded.upload_json,
              params_json=COALESCE(excluded.params_json,jobs.params_json),artifacts_json=excluded.artifacts_json,
              purged_at=excluded.purged_at
            """,
            data,
        )
        upsert_artifacts(job.get("id") or "", job.get("artifacts") or {})


def update_job(job: dict[str, Any]) -> None:
    init_db()
    data = _job_columns(job)
    with _LOCK:
        connect().execute(
            """
            UPDATE jobs SET
              name=:name,status=:status,updated_at=:updated_at,started_at=:started_at,finished_at=:finished_at,
              workspace_id=:workspace_id,email_mode=:email_mode,alias_prefix=:alias_prefix,
              count_per_account=:count_per_account,mailbox_count=:mailbox_count,total=:total,ok=:ok,failed=:failed,
              pending=:pending,concurrency=:concurrency,attempts=:attempts,out_dir=:out_dir,current_slot=:current_slot,
              error=:error,upload_json=:upload_json,artifacts_json=:artifacts_json,purged_at=:purged_at
            WHERE id=:id
            """,
            data,
        )
        upsert_artifacts(job.get("id") or "", job.get("artifacts") or {})


def _row_to_job(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    job = dict(row)
    job["upload"] = _json_loads(job.pop("upload_json", None), {})
    job["params"] = _json_loads(job.pop("params_json", None), {})
    artifacts = _json_loads(job.pop("artifacts_json", None), {})
    db_artifacts = get_artifacts(job["id"])
    job["artifacts"] = db_artifacts or artifacts or {}
    return job


def get_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    with _LOCK:
        row = connect().execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return _row_to_job(row)


def list_jobs(limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    with _LOCK:
        rows = connect().execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [job for row in rows if (job := _row_to_job(row))]


def append_log(job_id: str, item: dict[str, Any]) -> None:
    init_db()
    with _LOCK:
        connect().execute(
            """
            INSERT OR REPLACE INTO job_logs (job_id,seq,ts,message,line,created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (
                job_id,
                int(item.get("seq") or 0),
                str(item.get("ts") or ""),
                str(item.get("message") or ""),
                str(item.get("line") or ""),
                iso_now(),
            ),
        )


def get_logs(job_id: str, *, after: int = 0, limit: int = 1000) -> dict[str, Any]:
    init_db()
    with _LOCK:
        rows = connect().execute(
            """
            SELECT seq,ts,message,line FROM job_logs
            WHERE job_id=? AND seq>?
            ORDER BY seq ASC
            LIMIT ?
            """,
            (job_id, int(after), int(limit)),
        ).fetchall()
        max_row = connect().execute(
            "SELECT COALESCE(MAX(seq),0) AS last_seq FROM job_logs WHERE job_id=?",
            (job_id,),
        ).fetchone()
    return {
        "job_id": job_id,
        "last_seq": int(max_row["last_seq"] if max_row else 0),
        "logs": [dict(row) for row in rows],
    }


def upsert_results(job_id: str, results: list[dict[str, Any]]) -> None:
    if not results:
        return
    init_db()
    now = iso_now()
    rows = []
    for item in results:
        rows.append(
            (
                job_id,
                int(item.get("mailbox_index") or 0),
                int(item.get("slot") or 0),
                item.get("email") or "",
                item.get("base_email") or "",
                1 if item.get("ok") else 0,
                item.get("plan_type") or "",
                1 if item.get("workspace_joined") else 0,
                item.get("chatgpt_account_id") or "",
                item.get("elapsed_seconds"),
                item.get("error"),
                _json_dumps(item),
                now,
            )
        )
    with _LOCK:
        connect().executemany(
            """
            INSERT INTO job_results (
              job_id,mailbox_index,slot,email,base_email,ok,plan_type,workspace_joined,
              chatgpt_account_id,elapsed_seconds,error,result_json,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(job_id,mailbox_index,slot) DO UPDATE SET
              email=excluded.email,base_email=excluded.base_email,ok=excluded.ok,plan_type=excluded.plan_type,
              workspace_joined=excluded.workspace_joined,chatgpt_account_id=excluded.chatgpt_account_id,
              elapsed_seconds=excluded.elapsed_seconds,error=excluded.error,result_json=excluded.result_json,
              updated_at=excluded.updated_at
            """,
            rows,
        )
        _chmod_db_files()


def load_results(job_id: str) -> list[dict[str, Any]]:
    init_db()
    with _LOCK:
        rows = connect().execute(
            """
            SELECT result_json FROM job_results
            WHERE job_id=?
            ORDER BY slot ASC, mailbox_index ASC
            """,
            (job_id,),
        ).fetchall()
    return [_json_loads(row["result_json"], {}) for row in rows]


def upsert_artifacts(job_id: str, artifacts: dict[str, str]) -> None:
    if not job_id:
        return
    init_db()
    now = iso_now()
    with _LOCK:
        conn = connect()
        conn.execute("DELETE FROM job_artifacts WHERE job_id=?", (job_id,))
        if artifacts:
            conn.executemany(
                "INSERT OR REPLACE INTO job_artifacts (job_id,name,path,created_at) VALUES (?,?,?,?)",
                [(job_id, name, path, now) for name, path in artifacts.items()],
            )


def get_artifacts(job_id: str) -> dict[str, str]:
    init_db()
    with _LOCK:
        rows = connect().execute(
            "SELECT name,path FROM job_artifacts WHERE job_id=? ORDER BY name",
            (job_id,),
        ).fetchall()
    return {row["name"]: row["path"] for row in rows}


def mark_interrupted_jobs() -> int:
    init_db()
    now = iso_now()
    with _LOCK:
        cur = connect().execute(
            f"""
            UPDATE jobs
            SET status='interrupted', updated_at=?, finished_at=COALESCE(finished_at,?),
                error=COALESCE(error,'service restarted before job finished')
            WHERE status IN ({','.join('?' for _ in _RUNNING_STATUSES)})
            """,
            (now, now, *_RUNNING_STATUSES),
        )
        return int(cur.rowcount or 0)


def purge_sensitive_job_data(job_id: str) -> None:
    """Remove token-like values from DB result payloads after a successful upload."""
    init_db()
    now = iso_now()
    with _LOCK:
        conn = connect()
        rows = conn.execute(
            "SELECT mailbox_index,slot,result_json FROM job_results WHERE job_id=?",
            (job_id,),
        ).fetchall()
        for row in rows:
            payload = _json_loads(row["result_json"], {})
            payload = _sanitize_result_payload(payload)
            conn.execute(
                """
                UPDATE job_results
                SET result_json=?, updated_at=?
                WHERE job_id=? AND mailbox_index=? AND slot=?
                """,
                (_json_dumps(payload), now, job_id, row["mailbox_index"], row["slot"]),
            )
        conn.execute("UPDATE jobs SET purged_at=?, updated_at=? WHERE id=?", (now, now, job_id))
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")
        except sqlite3.DatabaseError:
            # Purge already happened logically; compaction is best-effort.
            pass
        _chmod_db_files()


def get_config(key: str = "control_form") -> dict[str, Any]:
    init_db()
    with _LOCK:
        row = connect().execute("SELECT value_json FROM app_config WHERE key=?", (key,)).fetchone()
    return _json_loads(row["value_json"] if row else None, {})


def save_config(value: dict[str, Any], key: str = "control_form") -> dict[str, Any]:
    init_db()
    # Never persist the console API key server-side; that remains browser-local.
    clean = dict(value or {})
    clean.pop("apiKey", None)
    now = iso_now()
    with _LOCK:
        connect().execute(
            """
            INSERT INTO app_config (key,value_json,updated_at) VALUES (?,?,?)
            ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
            """,
            (key, _json_dumps(clean), now),
        )
        _chmod_db_files()
    return {"ok": True, "updated_at": now, "config": clean}
