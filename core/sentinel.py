"""OpenAI Sentinel 工作量证明（PoW）。

严格对齐 newgpt2api/backend/internal/regkit/dispatcher/gpt/sentinel.go
（该实现又对齐 basketikun/chatgpt2api 的 Python 参考）。

关键算法：
  - configArray   : 18 字段的"反指纹"数组（顺序写死）
  - b64(v)        : json.dumps(v, separators=(",",":")) → base64.b64encode
                    禁止任何空格，否则 hash 不匹配
  - SolvePoW      : 暴力求解 i ∈ [0, 500000)，让 fnv1a_32(seed+payload) 的
                    hex 前缀 ≤ difficulty（字典序）
  - SentinelToken : POST /backend-api/sentinel/req 拿 seed/difficulty，
                    解 PoW，最终返回 openai-sentinel-token 头值（JSON 字符串）

必须用与下游 API 同一个 http client（共享 cookie / UA / proxy），否则 sentinel
后端会判 token 来源异常。
"""

from __future__ import annotations

import base64
import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from .pkce import new_device_id

logger = logging.getLogger(__name__)

_SENTINEL_MAX_ATTEMPTS = 500_000
_SENTINEL_ERR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
_SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js"

_VENDOR_FLAGS = (
    "vendorSub-undefined",
    "plugins-undefined",
    "mimeTypes-undefined",
    "hardwareConcurrency-undefined",
)
_DOC_FLAGS = ("location", "implementation", "URL", "documentURI", "compatMode")
_GLOBAL_FLAGS = ("Object", "Function", "Array", "Number", "parseFloat", "undefined")
_CORES = (4, 8, 12, 16)


def _fnv1a_32(data: bytes) -> int:
    """FNV-1a 32-bit hash。OpenAI sentinel 用它做 PoW。"""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _b64_compact(v: Any) -> str:
    """json.dumps(separators=(",",":")) + base64 标准编码（含 padding）。

    Go 默认 json.Marshal 也是 compact 输出（无空格），这里与之严格对齐。
    """
    raw = json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


@dataclass(slots=True)
class SentinelGenerator:
    """一个 task 持有一个 generator；deviceID / sid 在生命周期内固定。"""

    device_id: str
    user_agent: str
    sid: str = field(default_factory=new_device_id)
    resolution: str = "1920x1080"
    language: str = "en-US"
    cores: int = field(default_factory=lambda: random.choice(_CORES))
    history_len: int = 4_294_705_152
    flags_vendor: str = field(default_factory=lambda: random.choice(_VENDOR_FLAGS))
    flags_doc: str = field(default_factory=lambda: random.choice(_DOC_FLAGS))
    flags_global: str = field(default_factory=lambda: random.choice(_GLOBAL_FLAGS))

    def _config_array(self) -> list[Any]:
        """18 字段反指纹数组。布局严格对齐 Python ref / Go sentinel.go：

          [0]  屏幕分辨率
          [1]  当前 GMT 时间字符串（Mon Jan _2 2026 ...）
          [2]  history.length 等大数
          [3]  随机/迭代计数（SolvePoW 时被覆写）
          [4]  user-agent
          [5]  sentinel sdk.js URL
          [6]  null
          [7]  null
          [8]  navigator.language
          [9]  随机值（SolvePoW 时被覆写为 elapsed_ms）
          [10] vendor 反指纹标志
          [11] document 反指纹标志
          [12] global 反指纹标志
          [13] performance.now() 抖动
          [14] sid（UUID）
          [15] ""
          [16] hardwareConcurrency
          [17] (Date.now() * 1000 - perf_now)
        """
        perf_now = 1000.0 + random.random() * 49000.0
        rng = random.random()
        # Python time.strftime 不支持 Go 的 `_2`（前导空格的日），手工补齐
        now = time.gmtime()
        day_padded = f"{now.tm_mday:>2d}"
        tstr = time.strftime(
            f"%a %b {day_padded} %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
            now,
        )
        return [
            self.resolution,
            tstr,
            self.history_len,
            rng,
            self.user_agent,
            _SENTINEL_SDK_URL,
            None,
            None,
            self.language,
            rng,
            self.flags_vendor,
            self.flags_doc,
            self.flags_global,
            perf_now,
            self.sid,
            "",
            self.cores,
            float(int(time.time() * 1000)) - perf_now,
        ]

    def requirements_token(self) -> str:
        """先验 token，用于初次发 /sentinel/req 时携带。

        data[3]=1, data[9]=int(uniform(5,50))（与 Python ref 一致）。
        """
        data = self._config_array()
        data[3] = 1
        data[9] = float(int(5 + random.random() * 45))
        return "gAAAAAC" + _b64_compact(data)

    def solve_pow(self, seed: str, difficulty: str) -> str:
        """暴力求解 PoW。失败回到占位字符串（与 Python ref 一致）。"""
        if not difficulty:
            difficulty = "0"
        start = time.monotonic()
        data = self._config_array()
        seed_b = seed.encode("ascii")
        dl = len(difficulty)
        for i in range(_SENTINEL_MAX_ATTEMPTS):
            data[3] = i
            data[9] = float(int((time.monotonic() - start) * 1000))
            payload = _b64_compact(data)
            h = _fnv1a_32(seed_b + payload.encode("ascii"))
            hex_str = f"{h:08x}"
            cmp_len = min(dl, len(hex_str))
            if hex_str[:cmp_len] <= difficulty[:cmp_len]:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + _SENTINEL_ERR_PREFIX + _b64_compact(None)

    async def sentinel_token(
        self, client: httpx.AsyncClient, flow: str
    ) -> str:
        """完整 token：调 /sentinel/req → 解 PoW → 拼 JSON。

        失败重试一次；都失败时退化为 RequirementsToken 兜底（与 Python ref 一致：
        弱端点如 email-otp/validate 仍能继续，强端点如 create_account 可能拒）。
        """
        try:
            return await self._call_sentinel_req(client, flow)
        except Exception as e:  # noqa: BLE001
            logger.warning("sentinel/req 失败一次 (%s), 重试", e)
            try:
                return await self._call_sentinel_req(client, flow)
            except Exception as e2:  # noqa: BLE001
                logger.warning(
                    "sentinel/req 二次失败 (%s)，退化使用 fallback token", e2
                )
                return self._fallback_token(flow)

    async def _call_sentinel_req(
        self, client: httpx.AsyncClient, flow: str
    ) -> str:
        body = {
            "p": self.requirements_token(),
            "id": self.device_id,
            "flow": flow,
        }
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": "https://sentinel.openai.com",
            "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            "User-Agent": self.user_agent,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        # text/plain 但 body 实际是 JSON —— OpenAI 接受
        resp = await client.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            content=json.dumps(body, separators=(",", ":")),
            headers=headers,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"sentinel/req HTTP {resp.status_code}: {resp.text[:240]}"
            )
        data = resp.json()
        token = data.get("token") or ""
        if not token:
            raise RuntimeError(f"sentinel/req 响应缺 token: {resp.text[:240]}")
        pow_cfg = data.get("proofofwork") or {}
        if pow_cfg.get("required") and pow_cfg.get("seed"):
            p = self.solve_pow(pow_cfg["seed"], pow_cfg.get("difficulty") or "")
        else:
            p = self.requirements_token()
        out = {
            "p": p,
            "t": "",
            "c": token,
            "id": self.device_id,
            "flow": flow,
        }
        return json.dumps(out, separators=(",", ":"))

    def _fallback_token(self, flow: str) -> str:
        """sentinel.openai.com 完全不通时的兜底 token。"""
        out = {
            "p": self.requirements_token(),
            "t": "",
            "c": "",
            "id": self.device_id,
            "flow": flow,
        }
        return json.dumps(out, separators=(",", ":"))
