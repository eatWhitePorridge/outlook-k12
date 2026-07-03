"""CLI：命令行跑单个 / 批量注册，结果存 JSON。

用法：
  python -m gpt_register_lite.cli --config config.json
  python -m gpt_register_lite.cli --config config.json --count 5 --out results.json
  python -m gpt_register_lite.cli --config config.json --email me@example.com
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime
from typing import Optional

from .config import load_config
from .cloudmail import CloudMailClient
from .outlook import OutlookOAuthClient
from .register import AccountResult, register_and_auth


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


async def _run_one(
    client: CloudMailClient,
    cfg,
    *,
    email: Optional[str],
    idx: int,
    chatgpt_web_login: bool = False,
    workspace_id: str = "",
) -> dict:
    prefix = f"[#{idx}]"

    def _log(msg: str) -> None:
        print(f"{prefix} {msg}", flush=True)

    try:
        result: AccountResult = await register_and_auth(
            cloudmail=client,
            email=email,
            proxy=cfg.register_proxy,
            otp_max_retries=cfg.otp_max_retries,
            otp_poll_interval_s=cfg.otp_poll_interval_s,
            export_sub2api=cfg.export_sub2api,
            product_dir=cfg.product_dir,
            fetch_chatgpt_account_id=cfg.fetch_chatgpt_account_id,
            chatgpt_web_login=chatgpt_web_login or cfg.chatgpt_web_login,
            workspace_id=workspace_id or cfg.workspace_id,
            workspace_join_timeout_s=cfg.workspace_join_timeout_s,
            log=_log,
        )
        _log(f"✅ 成功 · {result.email} · 耗时 {result.duration_seconds:.1f}s")
        out = result.to_dict()
        out["ok"] = True
        return out
    except Exception as exc:  # noqa: BLE001
        _log(f"❌ 失败：{exc}")
        return {"ok": False, "email": email or "", "error": str(exc)}


async def _main_async(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if cfg.mail_backend == "outlook":
        if cfg.outlook is None:
            raise RuntimeError("mail_backend=outlook 但缺少 outlook 配置")
        client = OutlookOAuthClient(cfg.outlook)
    else:
        if cfg.cloudmail is None:
            raise RuntimeError("mail_backend=cloudmail 但缺少 cloudmail 配置")
        client = CloudMailClient(cfg.cloudmail)

    # 预登录一次（拿/缓存 token），失败早报错
    try:
        await client.login()
    except Exception as exc:  # noqa: BLE001
        print(f"{cfg.mail_backend} 登录失败：{exc}", file=sys.stderr)
        return 2

    results: list[dict] = []
    if args.email:
        results.append(
            await _run_one(
                client,
                cfg,
                email=args.email,
                idx=1,
                chatgpt_web_login=args.chatgpt_web,
                workspace_id=args.workspace_id,
            )
        )
    else:
        # 批量：串行跑，避免同 IP 并发触发风控
        for i in range(1, args.count + 1):
            results.append(
                await _run_one(
                    client,
                    cfg,
                    email=None,
                    idx=i,
                    chatgpt_web_login=args.chatgpt_web,
                    workspace_id=args.workspace_id,
                )
            )

    ok = sum(1 for r in results if r.get("ok"))
    print(f"\n完成 {ok}/{len(results)} 个", flush=True)

    out_path = args.out or f"results_{datetime.now():%Y%m%d_%H%M%S}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"结果写入 {out_path}", flush=True)

    return 0 if ok == len(results) else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gpt_register_lite",
        description="精简版 OpenAI 协议注册（创建 + auth，Cloud Mail 收码）",
    )
    parser.add_argument("--config", "-c", default="config.json", help="配置文件路径")
    parser.add_argument("--email", "-e", default=None, help="指定注册邮箱（不传则自动新建；Outlook 后端默认使用配置邮箱）")
    parser.add_argument("--count", "-n", type=int, default=1, help="批量注册数量（自动建邮箱时）")
    parser.add_argument("--out", "-o", default=None, help="结果 JSON 输出路径")
    parser.add_argument("--chatgpt-web", action="store_true", help="注册后走纯 ChatGPT Web flow，输出 backend-api AT")
    parser.add_argument("--workspace-id", default="", help="注册后加入该 ChatGPT workspace，并换 workspace-scoped Web AT")
    parser.add_argument("--verbose", "-v", action="store_true", help="输出底层日志")
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)
    try:
        return asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        print("\n中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
