"""端到端验证：浏览器跑 Codex SSO 拿 code → 协议层换 RT / account_id。

用法：
    python3 -m gpt_register_lite.test_codex_browser <email-or-account> [--headed] [--proxy URL]

账号必须是已在 example.com team 里、走 SSO 免密登录的账号。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

from .sso_browser import codex_get_refresh_token, codex_get_refresh_token_via_protocol_sso
from .sub2api import upload_product_payload


async def _main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("email")
    ap.add_argument("--headed", action="store_true", help="显示浏览器窗口（调试用）")
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument(
        "--chrome-profile",
        default=None,
        help="使用系统 Google Chrome 的持久 profile 目录（便于人工验证后复用状态）",
    )
    ap.add_argument(
        "--legacy-authorize",
        action="store_true",
        help="使用旧 authorize 参数（默认使用 Codex CLI simplified flow）",
    )
    ap.add_argument(
        "--manual-browser",
        action="store_true",
        help="不用 Playwright，打开真实浏览器并等待 localhost callback（适合 Cloudflare 人工验证）",
    )
    ap.add_argument(
        "--protocol-sso",
        action="store_true",
        help="纯协议 SAML SSO：直接 Codex OAuth，不启动浏览器（推荐）",
    )
    ap.add_argument(
        "--skip-team-login",
        action="store_true",
        help="兼容旧参数：当前纯协议路径默认就是直接 Codex OAuth",
    )
    ap.add_argument(
        "--join-team-first",
        action="store_true",
        help="调试旧链路：Codex OAuth 前先跑一次 ChatGPT web SSO 进 team",
    )
    ap.add_argument(
        "--sso-connection-id",
        default=os.environ.get("SSO_CONNECTION_ID") or "conn_xxxxxxxxxxxxxxxxxxxxxxxxxx",
        help="OpenAI WorkOS SSO connection id",
    )
    ap.add_argument(
        "--sso-base-url",
        default=os.environ.get("SSO_BASE_URL") or "https://sso.example.com",
        help="Authentik base URL",
    )
    ap.add_argument(
        "--auth-json",
        action="store_true",
        help="按 Codex auth.json 结构输出完整 token JSON",
    )
    ap.add_argument(
        "--product-json",
        action="store_true",
        help="按成品池/sub2api accounts 结构输出完整 token JSON",
    )
    ap.add_argument("--out", default=None, help="把 JSON 输出写入指定文件")
    ap.add_argument(
        "--hero-sms-key",
        default=os.environ.get("HERO_SMS_KEY") or os.environ.get("HERO_SMS_API_KEY"),
        help="hero-sms 接码 API key（add-phone 绑手机号时用）",
    )
    ap.add_argument(
        "--hero-sms-service",
        default=os.environ.get("HERO_SMS_SERVICE") or "dr",
        help="hero-sms service 代号（默认 dr=OpenAI）",
    )
    ap.add_argument(
        "--hero-sms-country",
        type=int,
        default=int(os.environ.get("HERO_SMS_COUNTRY") or 33),
        help="hero-sms 国家代号（默认 33=哥伦比亚）",
    )
    ap.add_argument(
        "--hero-sms-operator",
        default=os.environ.get("HERO_SMS_OPERATOR") or "",
        help="hero-sms 运营商（默认空=任意）",
    )
    ap.add_argument(
        "--hero-sms-max-price",
        type=float,
        default=(float(os.environ["HERO_SMS_MAX_PRICE"]) if os.environ.get("HERO_SMS_MAX_PRICE") else None),
        help="hero-sms 单号价格上限（默认不限）",
    )
    ap.add_argument(
        "--sub2api-upload",
        action="store_true",
        help="生成成功后自动上传到 sub2api 管理端",
    )
    ap.add_argument(
        "--sub2api-url",
        default=os.environ.get("SUB2API_BASE_URL") or "http://127.0.0.1:8080",
        help="sub2api base URL，默认 SUB2API_BASE_URL 或 http://127.0.0.1:8080",
    )
    ap.add_argument(
        "--sub2api-authorization",
        default=os.environ.get("SUB2API_AUTHORIZATION")
        or os.environ.get("SUB2API_BEARER_TOKEN")
        or os.environ.get("SUB2API_ADMIN_TOKEN"),
        help="sub2api Authorization header，可传完整 'Bearer ...'",
    )
    ap.add_argument(
        "--sub2api-admin-api-key",
        default=os.environ.get("SUB2API_ADMIN_API_KEY"),
        help="sub2api x-api-key 管理员 API Key（优先于 Authorization）",
    )
    ap.add_argument(
        "--sub2api-mode",
        choices=("batch", "data"),
        default=os.environ.get("SUB2API_UPLOAD_MODE") or "batch",
        help="上传接口：batch=/admin/accounts/batch，data=/admin/accounts/data",
    )
    ap.add_argument(
        "--sub2api-timeout",
        type=float,
        default=float(os.environ.get("SUB2API_TIMEOUT") or 30),
        help="sub2api 上传超时秒数",
    )
    args = ap.parse_args()
    sso_email_domain = os.environ.get("SSO_EMAIL_DOMAIN", "example.com")
    email = args.email if "@" in args.email else f"{args.email}@{sso_email_domain}"

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    def log(s: str) -> None:
        print(s, flush=True)

    try:
        if args.protocol_sso:
            sms_provider = None
            if args.hero_sms_key:
                from .sms_hero import HeroSmsClient, HeroSmsConfig
                sms_provider = HeroSmsClient(HeroSmsConfig(
                    api_key=args.hero_sms_key,
                    service=args.hero_sms_service,
                    country=args.hero_sms_country,
                    operator=args.hero_sms_operator,
                    max_price=args.hero_sms_max_price,
                    proxy=args.proxy,
                ))
            res = await codex_get_refresh_token_via_protocol_sso(
                email=email,
                proxy=args.proxy,
                timeout_s=args.timeout,
                sso_connection_id=args.sso_connection_id,
                sso_base_url=args.sso_base_url,
                join_team_first=args.join_team_first and not args.skip_team_login,
                sms_provider=sms_provider,
                log=log,
            )
        else:
            res = await codex_get_refresh_token(
                email=email,
                headless=not args.headed,
                proxy=args.proxy,
                timeout_s=args.timeout,
                chrome_profile=args.chrome_profile,
                simplified_flow=not args.legacy_authorize,
                manual_browser=args.manual_browser,
                log=log,
            )
    except Exception as exc:  # noqa: BLE001
        print(f"\n❌ 失败：{exc}", file=sys.stderr)
        return 1

    print("\n=== 成功 ===")
    product_data = _build_product_json(res) if args.product_json or args.sub2api_upload else None
    if args.auth_json or args.product_json:
        data = product_data if args.product_json else _build_auth_json(res)
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(payload)
                f.write("\n")
            print(f"json              : {args.out}")
            print(f"refresh_token     : {res.refresh_token[:24]}...{res.refresh_token[-12:]}")
        else:
            print(payload)
        if args.sub2api_upload:
            if not await _try_upload_to_sub2api(args, product_data):
                return 1
        return 0

    print(f"email             : {res.email}")
    print(f"chatgpt_account_id: {res.chatgpt_account_id}")
    print(f"plan_type         : {res.plan_type}")
    print(f"refresh_token     : {res.refresh_token[:40]}...")
    print(f"access_token      : {res.access_token[:40]}...")
    if args.sub2api_upload:
        if not await _try_upload_to_sub2api(args, product_data):
            return 1
    return 0


def _build_auth_json(res) -> dict:
    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": res.id_token,
            "access_token": res.access_token,
            "refresh_token": res.refresh_token,
            "account_id": res.chatgpt_account_id,
        },
        "last_refresh": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _email_key(email: str) -> str:
    key = re.sub(r"[^A-Za-z0-9]+", "_", email.strip().lower()).strip("_")
    return key or "openai_account"


def _build_product_json(res) -> dict:
    now = _utc_now()
    expires_in = int(res.expires_in or 0)
    expires_at_epoch = int(time.time()) + expires_in
    expires_at_iso = _iso_z(now + timedelta(seconds=expires_in))
    return {
        "exported_at": _iso_z(now),
        "proxies": [],
        "accounts": [
            {
                "name": res.email,
                "platform": "openai",
                "type": "oauth",
                "expires_at": expires_at_epoch,
                "auto_pause_on_expired": True,
                "concurrency": 10,
                "priority": 1,
                "credentials": {
                    "access_token": res.access_token,
                    "refresh_token": res.refresh_token,
                    "id_token": res.id_token,
                    "chatgpt_account_id": res.chatgpt_account_id,
                    "chatgpt_user_id": res.chatgpt_user_id,
                    "email": res.email,
                    "expires_at": expires_at_iso,
                    "expires_in": expires_in,
                    "plan_type": res.plan_type,
                },
                "extra": {
                    "email": res.email,
                    "email_key": _email_key(res.email),
                    "name": res.email,
                    "auth_provider": "openai",
                    "source": "chatgpt_web_session",
                    "last_refresh": _iso_z(now),
                    "sub": res.sub,
                },
            }
        ],
    }


async def _upload_to_sub2api(args, product_data: dict | None) -> None:
    if not product_data:
        raise RuntimeError("sub2api upload 需要 product JSON payload")
    result = await upload_product_payload(
        product_data,
        base_url=args.sub2api_url,
        authorization=args.sub2api_authorization,
        admin_api_key=args.sub2api_admin_api_key,
        mode=args.sub2api_mode,
        timeout_s=args.sub2api_timeout,
    )
    print("sub2api_upload    : ok")
    print(f"sub2api_endpoint  : {result['url']}")
    _print_sub2api_result(result.get("response"))


def _print_sub2api_result(body) -> None:
    if not isinstance(body, dict):
        return
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    if not isinstance(data, dict):
        return
    if "success" in data or "failed" in data:
        print(f"sub2api_result    : success={data.get('success', 0)} failed={data.get('failed', 0)}")
        return
    if "account_created" in data or "account_failed" in data:
        print(
            "sub2api_result    : "
            f"account_created={data.get('account_created', 0)} "
            f"account_failed={data.get('account_failed', 0)}"
        )


async def _try_upload_to_sub2api(args, product_data: dict | None) -> bool:
    try:
        await _upload_to_sub2api(args, product_data)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"❌ sub2api 上传失败：{exc}", file=sys.stderr)
        return False


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
