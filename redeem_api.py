"""Small redemption-code service for handing out saved OAuth account payloads.

Run separately from the account generator:
  python -m gpt_register_lite.redeem_api
"""
from __future__ import annotations

import hashlib
import html
import io
import json
import os
import base64
import re
import secrets
import sqlite3
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, Header, HTTPException, Query
    from fastapi.responses import HTMLResponse, Response
    from pydantic import BaseModel, Field
except ImportError as exc:  # noqa: BLE001
    raise RuntimeError("redeem service needs fastapi + uvicorn") from exc


APP_VERSION = "1.3"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _env(name: str, default: str) -> str:
    value = (os.environ.get(name) or "").strip()
    return value or default


def _db_path() -> Path:
    return Path(_env("REDEEM_DB", "/data/redeem/redeem.db"))


def _account_dir() -> Path:
    return Path(_env("REDEEM_ACCOUNT_DIR", "/data/saved_accounts"))


def _claimed_dir() -> Path:
    return Path(_env("REDEEM_CLAIMED_DIR", "/data/redeemed_accounts"))


def _admin_key() -> str:
    return (os.environ.get("REDEEM_ADMIN_KEY") or "").strip()


def _now() -> int:
    return int(time.time())


def _iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _iso_ms(ts: int) -> str:
    return (
        datetime.fromtimestamp(int(ts), tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _iso_now_ms() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalize_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _hash_code(code: str) -> str:
    normalized = _normalize_code(code)
    if not normalized:
        raise ValueError("empty code")
    pepper = (os.environ.get("REDEEM_CODE_PEPPER") or "").encode()
    return hashlib.sha256(pepper + normalized.encode()).hexdigest()


def _display_code(raw: str, *, group: int = 4) -> str:
    return "-".join(raw[i : i + group] for i in range(0, len(raw), group))


def _new_code(prefix: str, length: int) -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))
    normalized_prefix = _normalize_code(prefix)
    if normalized_prefix:
        raw = normalized_prefix + raw
    return _display_code(raw)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS redeem_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            max_redemptions INTEGER NOT NULL DEFAULT 1,
            redeem_count INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            redeemed_at INTEGER,
            redeemed_file TEXT,
            redeemed_account_name TEXT
        )
        """
    )
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(redeem_codes)").fetchall()
    }
    if "max_redemptions" not in columns:
        conn.execute(
            "ALTER TABLE redeem_codes ADD COLUMN max_redemptions INTEGER NOT NULL DEFAULT 1"
        )
    if "redeem_count" not in columns:
        conn.execute(
            "ALTER TABLE redeem_codes ADD COLUMN redeem_count INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute(
        """
        UPDATE redeem_codes
        SET redeem_count = max_redemptions
        WHERE status = 'redeemed'
          AND redeem_count = 0
          AND max_redemptions > 0
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_redeem_codes_status ON redeem_codes(status)")
    return conn


def _check_admin(
    x_admin_key: Optional[str],
    authorization: Optional[str],
) -> None:
    expected = _admin_key()
    if not expected:
        raise HTTPException(status_code=503, detail="REDEEM_ADMIN_KEY is not configured")
    bearer = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()
    if x_admin_key != expected and bearer != expected:
        raise HTTPException(status_code=401, detail="invalid admin key")


def _count_json_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for _ in path.glob("*.json"))


def _load_account_payload(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    accounts = data.get("accounts") or []
    if not accounts:
        raise ValueError("payload has no accounts")
    credentials = accounts[0].get("credentials") or {}
    if not credentials.get("access_token"):
        raise ValueError("payload has no access_token")
    if not credentials.get("refresh_token"):
        raise ValueError("payload has no refresh_token")
    return data


def _b64url_json(value: dict) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")
    return slug or "unknown"


def _synthetic_email(account_id: str) -> str:
    return f"openai-{_safe_slug(account_id)[:36]}@cpa.local"


def _synthetic_id_token(
    *,
    account_id: str,
    chatgpt_user_id: str,
    plan_type: str,
    email: str,
    exp: int,
) -> str:
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT", "cpa_synthetic": True}
    payload = {
        "iat": now,
        "exp": int(exp),
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_plan_type": plan_type,
            "chatgpt_user_id": chatgpt_user_id,
            "user_id": chatgpt_user_id,
        },
        "email": email,
    }
    return f"{_b64url_json(header)}.{_b64url_json(payload)}.synthetic"


def _first_account(payload: dict) -> dict:
    accounts = payload.get("accounts") or []
    if not accounts:
        raise ValueError("payload has no accounts")
    return accounts[0]


def _to_cpa_payload(payload: dict) -> dict:
    account = _first_account(payload)
    credentials = account.get("credentials") or {}
    access_token = credentials.get("access_token") or ""
    refresh_token = credentials.get("refresh_token") or ""
    access_payload = _decode_jwt_payload(access_token)
    auth_info = access_payload.get("https://api.openai.com/auth") or {}

    account_id = (
        credentials.get("chatgpt_account_id")
        or auth_info.get("chatgpt_account_id")
        or account.get("name")
        or "unknown-account"
    )
    chatgpt_user_id = (
        credentials.get("chatgpt_user_id")
        or auth_info.get("chatgpt_user_id")
        or auth_info.get("user_id")
        or ""
    )
    plan_type = (
        credentials.get("plan_type")
        or account.get("plan_type")
        or auth_info.get("chatgpt_plan_type")
        or "unknown"
    )
    exp = access_payload.get("exp")
    if not isinstance(exp, int) or exp <= 0:
        exp = int(time.time()) + int(credentials.get("expires_in") or 864000)

    email = _synthetic_email(str(account_id))
    id_token = credentials.get("id_token") or _synthetic_id_token(
        account_id=str(account_id),
        chatgpt_user_id=str(chatgpt_user_id),
        plan_type=str(plan_type),
        email=email,
        exp=int(exp),
    )
    return {
        "type": "codex",
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "email": email,
        "name": email,
        "plan_type": plan_type,
        "chatgpt_plan_type": plan_type,
        "id_token": id_token,
        "id_token_synthetic": not bool(credentials.get("id_token")),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_token": credentials.get("session_token") or "",
        "last_refresh": _iso_now_ms(),
        "expired": _iso_ms(int(exp)),
    }


def _merge_sub2api_payloads(payloads: list[dict]) -> dict:
    accounts: list[dict] = []
    for payload in payloads:
        accounts.extend(payload.get("accounts") or [])
    return {
        "exported_at": _iso_now_ms(),
        "proxies": [],
        "accounts": accounts,
    }


def _download_response(payloads: list[dict] | dict, *, fmt: str, extra_headers: Optional[dict[str, str]] = None) -> Response:
    normalized = (fmt or "sub2api").strip().lower()
    if normalized not in {"sub2api", "cpa"}:
        raise HTTPException(status_code=400, detail="format must be sub2api or cpa")
    payload_list = [payloads] if isinstance(payloads, dict) else payloads
    if not payload_list:
        raise HTTPException(status_code=500, detail="no payloads to download")
    account = _first_account(payload_list[0])
    credentials = account.get("credentials") or {}
    account_id = (
        credentials.get("chatgpt_account_id")
        or account.get("name")
        or str(int(time.time()))
    )
    if normalized == "cpa" and len(payload_list) > 1:
        filename = f"cpa_batch_{len(payload_list)}_{_safe_slug(str(account_id))}.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for idx, payload in enumerate(payload_list, 1):
                cpa_payload = _to_cpa_payload(payload)
                cpa_account_id = _safe_slug(
                    str(cpa_payload.get("chatgpt_account_id") or cpa_payload.get("account_id") or idx)
                )
                zf.writestr(
                    f"cpa_{idx:03d}_{cpa_account_id}.json",
                    json.dumps(cpa_payload, ensure_ascii=False, indent=2) + "\n",
                )
        content = buf.getvalue()
        media_type = "application/zip"
    else:
        body = _to_cpa_payload(payload_list[0]) if normalized == "cpa" else _merge_sub2api_payloads(payload_list)
        filename = f"{normalized}_{len(payload_list)}_{_safe_slug(str(account_id))}.json"
        content = (json.dumps(body, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        media_type = "application/json"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Redeem-Format": normalized,
        "X-Accounts-Delivered": str(len(payload_list)),
    }
    if extra_headers:
        headers.update(extra_headers)
    return Response(
        content=content,
        media_type=media_type,
        headers=headers,
    )


def _next_account_file() -> Path:
    account_dir = _account_dir()
    account_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(account_dir.glob("*.json"), key=lambda p: (p.stat().st_mtime, p.name))
    for path in files:
        try:
            _load_account_payload(path)
            return path
        except Exception:
            continue
    raise RuntimeError("no valid account files available")


def _next_account_files(count: int) -> list[Path]:
    account_dir = _account_dir()
    account_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(account_dir.glob("*.json"), key=lambda p: (p.stat().st_mtime, p.name))
    selected: list[Path] = []
    for path in files:
        try:
            _load_account_payload(path)
        except Exception:
            continue
        selected.append(path)
        if len(selected) >= count:
            break
    if len(selected) < count:
        raise RuntimeError(f"not enough valid account files available: need {count}, got {len(selected)}")
    return selected


class RedeemReq(BaseModel):
    code: str = Field(..., min_length=1, max_length=128)
    format: str = Field("sub2api", max_length=16)


class GenerateReq(BaseModel):
    count: int = Field(1, ge=1, le=1000)
    prefix: str = Field("", max_length=16)
    code_length: int = Field(16, ge=8, le=48)
    max_redemptions: int = Field(1, ge=1, le=1000)
    expires_in_seconds: Optional[int] = Field(default=None, ge=60)
    label: str = Field("", max_length=128)


app = FastAPI(title="gpt_register_lite_redeem", version=APP_VERSION)


@app.on_event("startup")
async def _startup() -> None:
    _connect().close()


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "version": APP_VERSION}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page() -> str:
    return """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>兑换码管理</title>
  <style>
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f6f7f8;color:#171717}
    main{max-width:980px;margin:48px auto;padding:0 20px}
    section{background:#fff;border:1px solid #ddd;border-radius:8px;padding:22px;margin-bottom:16px}
    h1{font-size:24px;margin:0 0 18px}
    h2{font-size:18px;margin:0 0 14px}
    .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
    label{font-size:13px;color:#555;display:block;margin-bottom:6px}
    input{box-sizing:border-box;width:100%;font-size:16px;padding:10px;border:1px solid #c9c9c9;border-radius:6px}
    button{margin-top:12px;padding:10px 14px;border:0;border-radius:6px;background:#111;color:#fff;font-size:15px;cursor:pointer}
    button.secondary{background:#555}
    pre{white-space:pre-wrap;word-break:break-all;background:#111;color:#f5f5f5;border-radius:6px;padding:14px;overflow:auto}
    table{width:100%;border-collapse:collapse;font-size:14px}
    th,td{border-bottom:1px solid #e5e5e5;text-align:left;padding:8px}
    .muted{color:#666;font-size:13px}
    @media (max-width:720px){.grid{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>兑换码管理</h1>
      <div class="grid">
        <div>
          <label>Admin Key</label>
          <input id="key" type="password" autocomplete="current-password">
        </div>
        <div>
          <label>标签</label>
          <input id="label" value="batch">
        </div>
        <div>
          <label>生成多少个兑换码</label>
          <input id="count" type="number" min="1" max="1000" value="10">
        </div>
        <div>
          <label>每个兑换码可兑换账号数</label>
          <input id="max_redemptions" type="number" min="1" max="1000" value="1">
        </div>
        <div>
          <label>兑换码前缀</label>
          <input id="prefix" value="NV">
        </div>
        <div>
          <label>随机码长度</label>
          <input id="code_length" type="number" min="8" max="48" value="16">
        </div>
        <div>
          <label>过期秒数</label>
          <input id="expires_in_seconds" type="number" min="60" placeholder="留空不过期">
        </div>
      </div>
      <button onclick="generate()">生成兑换码</button>
      <button class="secondary" onclick="refreshStats()">刷新统计</button>
      <pre id="out" hidden></pre>
    </section>
    <section>
      <h2>统计</h2>
      <pre id="stats">尚未加载</pre>
    </section>
    <section>
      <h2>最近兑换码</h2>
      <div id="codes" class="muted">尚未加载</div>
    </section>
  </main>
  <script>
    const keyInput = document.getElementById('key');
    keyInput.value = localStorage.getItem('redeem_admin_key') || '';
    keyInput.addEventListener('change', () => localStorage.setItem('redeem_admin_key', keyInput.value));
    function adminHeaders(){
      return {'Content-Type':'application/json', 'X-Admin-Key': keyInput.value};
    }
    function intValue(id, fallback){
      const value = document.getElementById(id).value;
      if(value === '') return fallback;
      const parsed = Number.parseInt(value, 10);
      return Number.isFinite(parsed) ? parsed : fallback;
    }
    async function generate(){
      localStorage.setItem('redeem_admin_key', keyInput.value);
      const body = {
        count: intValue('count', 1),
        prefix: document.getElementById('prefix').value,
        code_length: intValue('code_length', 16),
        max_redemptions: intValue('max_redemptions', 1),
        label: document.getElementById('label').value
      };
      const expires = document.getElementById('expires_in_seconds').value;
      if(expires) body.expires_in_seconds = Number.parseInt(expires, 10);
      const out = document.getElementById('out');
      out.hidden = false;
      out.textContent = '生成中...';
      const resp = await fetch('/admin/codes/generate', {
        method:'POST',
        headers: adminHeaders(),
        body: JSON.stringify(body)
      });
      const data = await resp.json().catch(() => ({error:'invalid response'}));
      out.textContent = JSON.stringify(data, null, 2);
      await refreshStats();
    }
    async function refreshStats(){
      localStorage.setItem('redeem_admin_key', keyInput.value);
      const statsResp = await fetch('/admin/stats', {headers: adminHeaders()});
      const stats = await statsResp.json().catch(() => ({error:'invalid stats'}));
      document.getElementById('stats').textContent = JSON.stringify(stats, null, 2);
      const codesResp = await fetch('/admin/codes?limit=30', {headers: adminHeaders()});
      const codes = await codesResp.json().catch(() => ({items:[]}));
      const rows = (codes.items || []).map(item => `
        <tr>
          <td>${item.id}</td>
          <td>${item.label || ''}</td>
          <td>${item.status}</td>
          <td>${item.redeem_count}/${item.max_redemptions}</td>
          <td>${item.created_at}</td>
          <td>${item.redeemed_at || ''}</td>
        </tr>`).join('');
      document.getElementById('codes').innerHTML = rows
        ? `<table><thead><tr><th>ID</th><th>标签</th><th>状态</th><th>已兑/总数</th><th>创建</th><th>最近兑换</th></tr></thead><tbody>${rows}</tbody></table>`
        : JSON.stringify(codes, null, 2);
    }
    if(keyInput.value) refreshStats();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>兑换账号</title>
  <style>
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f6f7f8;color:#171717}
    main{max-width:720px;margin:72px auto;padding:0 20px}
    section{background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px}
    h1{font-size:24px;margin:0 0 18px}
    input,select{box-sizing:border-box;width:100%;font-size:18px;padding:12px;border:1px solid #c9c9c9;border-radius:6px}
    label{display:block;margin:14px 0 6px;font-size:13px;color:#555}
    button{margin-top:12px;padding:11px 16px;border:0;border-radius:6px;background:#111;color:#fff;font-size:16px;cursor:pointer}
    pre{white-space:pre-wrap;word-break:break-all;background:#111;color:#f5f5f5;border-radius:6px;padding:16px;overflow:auto}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>兑换账号</h1>
      <label>兑换码</label>
      <input id="code" autocomplete="one-time-code" placeholder="输入兑换码">
      <label>下载格式</label>
      <select id="format">
        <option value="sub2api">sub2api</option>
        <option value="cpa">CPA</option>
      </select>
      <button onclick="redeem()">兑换并下载</button>
      <pre id="out" hidden></pre>
    </section>
  </main>
  <script>
    async function redeem(){
      const out = document.getElementById('out');
      out.hidden = false;
      out.textContent = '兑换中...';
      const code = document.getElementById('code').value;
      const format = document.getElementById('format').value;
      const resp = await fetch('/redeem', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({code, format})
      });
      if(!resp.ok){
        const data = await resp.json().catch(() => ({detail:'invalid response'}));
        out.textContent = JSON.stringify(data, null, 2);
        return;
      }
      const blob = await resp.blob();
      const disposition = resp.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="([^"]+)"/);
      const filename = match ? match[1] : `${format}_account.json`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      out.textContent = JSON.stringify({
        ok: true,
        downloaded: filename,
        format: resp.headers.get('x-redeem-format') || format,
        accounts_delivered: resp.headers.get('x-accounts-delivered'),
        redeem_count: resp.headers.get('x-redeem-count'),
        max_redemptions: resp.headers.get('x-max-redemptions'),
        remaining_redemptions: resp.headers.get('x-remaining-redemptions')
      }, null, 2);
    }
  </script>
</body>
</html>
"""


@app.post("/redeem")
async def redeem(req: RedeemReq) -> Response:
    code_hash = _hash_code(req.code)
    now = _now()
    fmt = req.format.strip().lower()
    if fmt not in {"sub2api", "cpa"}:
        raise HTTPException(status_code=400, detail="format must be sub2api or cpa")
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM redeem_codes WHERE code_hash = ?",
            (code_hash,),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise HTTPException(status_code=404, detail="invalid code")
        if row["status"] != "active":
            conn.execute("ROLLBACK")
            raise HTTPException(status_code=409, detail=f"code is {row['status']}")
        max_redemptions = max(1, int(row["max_redemptions"] or 1))
        redeem_count = max(0, int(row["redeem_count"] or 0))
        if redeem_count >= max_redemptions:
            conn.execute(
                "UPDATE redeem_codes SET status = 'redeemed' WHERE id = ?",
                (row["id"],),
            )
            conn.execute("COMMIT")
            raise HTTPException(status_code=409, detail="code is redeemed")
        if row["expires_at"] is not None and int(row["expires_at"]) < now:
            conn.execute(
                "UPDATE redeem_codes SET status = 'expired' WHERE id = ?",
                (row["id"],),
            )
            conn.execute("COMMIT")
            raise HTTPException(status_code=410, detail="code expired")

        batch_size = max_redemptions - redeem_count
        sources = _next_account_files(batch_size)
        payloads = [_load_account_payload(src) for src in sources]
        response = _download_response(payloads, fmt=fmt)
        account_names = [
            str((payload.get("accounts") or [{}])[0].get("name") or "")
            for payload in payloads
        ]
        claimed_dir = _claimed_dir()
        claimed_dir.mkdir(parents=True, exist_ok=True)
        destinations: list[Path] = []
        for idx, src in enumerate(sources, 1):
            dst = claimed_dir / f"{now}_{idx:03d}_{src.name}"
            src.rename(dst)
            destinations.append(dst)
        next_count = max_redemptions
        next_status = "redeemed"

        conn.execute(
            """
            UPDATE redeem_codes
            SET status = ?,
                redeemed_at = ?,
                redeemed_file = ?,
                redeemed_account_name = ?,
                redeem_count = ?
            WHERE id = ?
            """,
            (
                next_status,
                now,
                json.dumps([str(path) for path in destinations], ensure_ascii=False),
                f"batch:{len(account_names)}",
                next_count,
                row["id"],
            ),
        )
        conn.execute("COMMIT")
        response.headers["X-Redeemed-At"] = _iso(now)
        response.headers["X-Redeem-Count"] = str(next_count)
        response.headers["X-Max-Redemptions"] = str(max_redemptions)
        response.headers["X-Remaining-Redemptions"] = str(max_redemptions - next_count)
        response.headers["X-Accounts-Delivered"] = str(len(payloads))
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        conn.close()


@app.post("/admin/codes/generate")
async def generate_codes(
    req: GenerateReq,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> dict:
    _check_admin(x_admin_key, authorization)
    now = _now()
    expires_at = now + req.expires_in_seconds if req.expires_in_seconds else None
    codes: list[str] = []
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        while len(codes) < req.count:
            code = _new_code(req.prefix, req.code_length)
            try:
                conn.execute(
                    """
                    INSERT INTO redeem_codes
                        (
                            code_hash, label, status, max_redemptions,
                            redeem_count, created_at, expires_at
                        )
                    VALUES (?, ?, 'active', ?, 0, ?, ?)
                    """,
                    (_hash_code(code), req.label, req.max_redemptions, now, expires_at),
                )
            except sqlite3.IntegrityError:
                continue
            codes.append(code)
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()
    return {
        "ok": True,
        "count": len(codes),
        "max_redemptions": req.max_redemptions,
        "total_accounts": len(codes) * req.max_redemptions,
        "expires_at": _iso(expires_at) if expires_at else None,
        "codes": codes,
    }


@app.get("/admin/stats")
async def stats(
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> dict:
    _check_admin(x_admin_key, authorization)
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM redeem_codes GROUP BY status"
        ).fetchall()
    finally:
        conn.close()
    by_status = {row["status"]: int(row["n"]) for row in rows}
    return {
        "ok": True,
        "codes": by_status,
        "pool_count": _count_json_files(_account_dir()),
        "claimed_count": _count_json_files(_claimed_dir()),
    }


@app.get("/admin/codes")
async def list_codes(
    limit: int = Query(50, ge=1, le=500),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> dict:
    _check_admin(x_admin_key, authorization)
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, label, status, max_redemptions, redeem_count,
                   created_at, expires_at, redeemed_at, redeemed_account_name
            FROM redeem_codes
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    items = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "label": row["label"],
                "status": row["status"],
                "max_redemptions": row["max_redemptions"],
                "redeem_count": row["redeem_count"],
                "created_at": _iso(row["created_at"]),
                "expires_at": _iso(row["expires_at"]) if row["expires_at"] else None,
                "redeemed_at": _iso(row["redeemed_at"]) if row["redeemed_at"] else None,
                "redeemed_account_name": html.escape(row["redeemed_account_name"] or ""),
            }
        )
    return {"ok": True, "items": items}


def main() -> None:
    import uvicorn

    host = _env("HOST", "127.0.0.1")
    port = int(_env("PORT", "8010"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
