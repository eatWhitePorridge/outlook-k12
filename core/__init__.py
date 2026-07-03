"""协议底层模块（从 GPT_PLUS 纯协议版移植，未改动）。

- pkce        : PKCE / device_id / state / nonce
- profile     : 浏览器指纹（UA / sec-ch-ua / locale）
- http_client : httpx 客户端 + 标准头 + OAuth 常量
- sentinel    : OpenAI Sentinel PoW
"""
