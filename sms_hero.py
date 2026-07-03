"""hero-sms（sms-provider.example.com）短信接码客户端 —— 官方 sms-activate 兼容 API。

用于给 OpenAI 账号 add-phone：取一个真实手机号、轮询收 OpenAI 短信验证码。

鉴权走官方 API key（在 hero-sms 后台申请），比浏览器 cookie 稳，不会过期。

API 约定（核实自 https://sms-provider.example.com/cn/api ，与 sms-activate 协议兼容）：
  handler: https://sms-provider.example.com/stubs/handler_api.php
  鉴权:   query 参数 api_key=<KEY>
  - 取号:  ?action=getNumberV2&service=<svc>&country=<id>[&operator=&maxPrice=&fixedPrice=]
            -> JSON {activationId, phoneNumber, ...}（phoneNumber 纯数字含国家码不含 +）
            兜底 ?action=getNumber -> 文本 "ACCESS_NUMBER:<id>:<phone>"
  - 取码:  ?action=getStatus&id=<id>
            -> "STATUS_WAIT_CODE"（等）/ "STATUS_OK:<code>"（到码）/ "STATUS_CANCEL" 等
  - 完成:  ?action=setStatus&id=<id>&status=6
  - 取消:  ?action=setStatus&id=<id>&status=8

service 'dr' = OpenAI/ChatGPT；country 33 = 哥伦比亚（HAR 实测成功的组合）。
号码统一拼成 E.164：确保以 '+' 开头（phoneNumber 已含国家码）。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

HERO_HANDLER = "https://sms-provider.example.com/stubs/handler_api.php"


@dataclass(slots=True)
class HeroSmsConfig:
    api_key: str
    service: str = "dr"                   # OpenAI/ChatGPT 的 service 代号
    country: int = 33                     # 国家代号（33=哥伦比亚，HAR 实测成功）
    operator: str = ""                    # 运营商（空=任意）
    max_price: Optional[float] = None     # 最高价格上限（None=不限）
    poll_interval_s: float = 5.0
    poll_timeout_s: float = 180.0
    timeout_s: float = 30.0
    proxy: Optional[str] = None


@dataclass(slots=True)
class HeroNumber:
    activation_id: str
    phone_e164: str                       # +57...（可直接交给 OpenAI）


def _to_e164(phone: str) -> str:
    p = str(phone).strip()
    return p if p.startswith("+") else "+" + p.lstrip("+")


class HeroSmsClient:
    """hero-sms 接码客户端（sms-activate 兼容 API）。"""

    def __init__(self, cfg: HeroSmsConfig):
        self.cfg = cfg

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.cfg.timeout_s, proxy=self.cfg.proxy)

    async def _call(self, c: httpx.AsyncClient, params: dict) -> httpx.Response:
        params = {"api_key": self.cfg.api_key, **params}
        return await c.get(HERO_HANDLER, params=params)

    async def acquire_number(self, log=None) -> HeroNumber:
        """取一个号。优先 getNumberV2（JSON），失败兜底 getNumber（文本）。"""
        info = log or logger.info
        params = {
            "action": "getNumberV2",
            "service": self.cfg.service,
            "country": self.cfg.country,
        }
        if self.cfg.operator:
            params["operator"] = self.cfg.operator
        if self.cfg.max_price is not None:
            params["maxPrice"] = self.cfg.max_price
            params["fixedPrice"] = "true"

        async with self._client() as c:
            r = await self._call(c, params)
            body = (r.text or "").strip()
            # getNumberV2 成功返回 JSON
            if r.status_code == 200 and body.startswith("{"):
                data = r.json()
                act_id = str(data.get("activationId") or data.get("id") or "")
                phone = str(data.get("phoneNumber") or data.get("phone") or "")
                if act_id and phone:
                    num = HeroNumber(act_id, _to_e164(phone))
                    info(f"📱 [hero-sms] 取号 id={num.activation_id} phone={num.phone_e164}")
                    return num
            # 兜底：文本协议 getNumber -> ACCESS_NUMBER:<id>:<phone>
            if not body.startswith("ACCESS_NUMBER"):
                r2 = await self._call(c, {**params, "action": "getNumber"})
                body = (r2.text or "").strip()
            if body.startswith("ACCESS_NUMBER"):
                parts = body.split(":")
                if len(parts) >= 3:
                    num = HeroNumber(parts[1], _to_e164(parts[2]))
                    info(f"📱 [hero-sms] 取号 id={num.activation_id} phone={num.phone_e164}")
                    return num
        raise RuntimeError(f"[hero-sms] 取号失败: {body[:200]}")

    async def poll_code(self, activation_id: str, log=None) -> str:
        """轮询 getStatus 拿短信码。超时抛错。"""
        info = log or logger.info
        deadline = asyncio.get_event_loop().time() + self.cfg.poll_timeout_s
        attempt = 0
        async with self._client() as c:
            while True:
                attempt += 1
                r = await self._call(c, {"action": "getStatus", "id": activation_id})
                body = (r.text or "").strip()
                if body.startswith("STATUS_OK"):
                    code = body.split(":", 1)[1].strip() if ":" in body else ""
                    if code:
                        info(f"📨 [hero-sms] 收到验证码: {code}")
                        return code
                elif body and not body.startswith("STATUS_WAIT"):
                    # STATUS_CANCEL / 其他终态：直接失败，别空等
                    raise RuntimeError(f"[hero-sms] 激活终止: {body[:100]}")
                if asyncio.get_event_loop().time() >= deadline:
                    raise RuntimeError(
                        f"[hero-sms] 轮询超时（{self.cfg.poll_timeout_s}s, {attempt} 次）未收到短信码"
                    )
                await asyncio.sleep(self.cfg.poll_interval_s)

    async def release(self, activation_id: str) -> None:
        """取消激活（status=8）。失败静默。"""
        try:
            async with self._client() as c:
                await self._call(c, {"action": "setStatus", "id": activation_id, "status": 8})
        except Exception as exc:  # noqa: BLE001
            logger.warning("[hero-sms] 释放 %s 失败: %s", activation_id, exc)


__all__ = ["HeroSmsConfig", "HeroNumber", "HeroSmsClient"]
