"""Pack one-account JSON files into a single sub2api import payload."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_account(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    accounts = data.get("accounts") or []
    if len(accounts) != 1:
        raise ValueError(f"{path} must contain exactly one account")
    account = accounts[0]
    credentials = account.get("credentials") or {}
    if not credentials.get("access_token"):
        raise ValueError(f"{path} has no credentials.access_token")
    if not credentials.get("refresh_token"):
        raise ValueError(f"{path} has no credentials.refresh_token")
    return account


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dir",
        default="/data/saved_accounts",
        help="directory containing one-account JSON files",
    )
    ap.add_argument("--count", type=int, default=30, help="number of newest files to pack")
    ap.add_argument(
        "--out",
        default="/data/sub2api_batches/sub2api_batch.json",
        help="output JSON path",
    )
    ap.add_argument(
        "--move-to",
        default="",
        help="optional directory to move packed source files into",
    )
    args = ap.parse_args()

    source_dir = Path(args.dir)
    files = sorted(source_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    selected = files[: max(1, args.count)]
    if not selected:
        raise SystemExit(f"no JSON files found in {source_dir}")

    accounts = [_load_account(path) for path in selected]
    payload = {
        "exported_at": _iso_now(),
        "proxies": [],
        "accounts": accounts,
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.move_to:
        move_to = Path(args.move_to)
        move_to.mkdir(parents=True, exist_ok=True)
        for path in selected:
            path.rename(move_to / path.name)

    print(
        json.dumps(
            {
                "ok": True,
                "out": str(out),
                "accounts": len(accounts),
                "moved_to": args.move_to or None,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
