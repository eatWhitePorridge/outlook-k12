"""Convert saved Codex OAuth accounts into CPA auth-file JSON.

The CPA uploader in the sibling project uploads one account per JSON file via
multipart form field "file". This script keeps that as the default, while also
offering an array output for archiving or importers that explicitly support it.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _b64url_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def _iso_from_epoch(epoch: int | None) -> str:
    if not epoch:
        return ""
    return (
        datetime.fromtimestamp(int(epoch), tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _iso_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
    payload = {
        "iat": now,
        "exp": exp,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_plan_type": plan_type,
            "chatgpt_user_id": chatgpt_user_id,
            "user_id": chatgpt_user_id,
        },
        "email": email,
    }
    header = {"alg": "none", "typ": "JWT", "cpa_synthetic": True}
    return f"{_b64url_json(header)}.{_b64url_json(payload)}.synthetic"


def _load_saved_account(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    accounts = data.get("accounts") or []
    if len(accounts) != 1:
        raise ValueError(f"{path} must contain exactly one account")
    account = accounts[0]
    credentials = account.get("credentials") or {}
    access_token = credentials.get("access_token") or ""
    if not access_token:
        raise ValueError(f"{path} has no credentials.access_token")
    return account


def _to_cpa_account(account: dict[str, Any], *, use_token_email: bool) -> dict[str, Any]:
    credentials = account.get("credentials") or {}
    access_token = credentials.get("access_token") or ""
    refresh_token = credentials.get("refresh_token") or ""
    access_payload = _decode_jwt_payload(access_token)
    auth_info = access_payload.get("https://api.openai.com/auth") or {}
    profile_info = access_payload.get("https://api.openai.com/profile") or {}

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
    plan_type = credentials.get("plan_type") or account.get("plan_type") or auth_info.get("chatgpt_plan_type") or "unknown"
    exp = access_payload.get("exp")
    if not isinstance(exp, int) or exp <= 0:
        exp = int(time.time()) + int(credentials.get("expires_in") or 0)
    if exp <= int(time.time()):
        exp = int(time.time()) + 864000

    token_email = profile_info.get("email") if isinstance(profile_info, dict) else ""
    email = token_email if use_token_email and token_email else _synthetic_email(str(account_id))
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
        "last_refresh": _iso_now(),
        "expired": _iso_from_epoch(int(exp)),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="/data/saved_accounts", help="directory containing saved sub2api JSON files")
    ap.add_argument("--count", type=int, default=30, help="number of newest files to convert")
    ap.add_argument(
        "--format",
        choices=("files", "array"),
        default="files",
        help="files = one CPA JSON per account; array = one JSON array file",
    )
    ap.add_argument("--out-dir", default="/data/cpa_accounts", help="output directory for --format files")
    ap.add_argument("--out", default="/data/cpa_batches/cpa_batch.json", help="output path for --format array")
    ap.add_argument("--move-to", default="", help="optional directory to move converted source files into")
    ap.add_argument(
        "--use-token-email",
        action="store_true",
        help="use email embedded in the access token profile claim instead of synthetic cpa.local email",
    )
    args = ap.parse_args()

    source_dir = Path(args.dir)
    files = sorted(source_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    selected = files[: max(1, args.count)]
    if not selected:
        raise SystemExit(f"no JSON files found in {source_dir}")

    converted = [_to_cpa_account(_load_saved_account(path), use_token_email=args.use_token_email) for path in selected]

    outputs: list[str] = []
    if args.format == "array":
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(converted, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        outputs.append(str(out))
    else:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for item in converted:
            account_id = _safe_slug(str(item.get("chatgpt_account_id") or item.get("account_id") or "unknown"))
            path = out_dir / f"{int(time.time_ns())}_{account_id}.json"
            path.write_text(json.dumps(item, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            outputs.append(str(path))

    if args.move_to:
        move_to = Path(args.move_to)
        move_to.mkdir(parents=True, exist_ok=True)
        for path in selected:
            path.rename(move_to / path.name)

    print(
        json.dumps(
            {
                "ok": True,
                "format": args.format,
                "accounts": len(converted),
                "outputs": outputs[:5],
                "outputs_total": len(outputs),
                "moved_to": args.move_to or None,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
