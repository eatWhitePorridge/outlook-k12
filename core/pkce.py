"""PKCE / device_id / base64url / uuid 工具。

严格对齐 newgpt2api sentinel.go：
  - PKCE verifier = base64url(64 random bytes)  ← 字节数关键
  - PKCE challenge = base64url(sha256(verifier))
  - device_id = UUIDv4
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from dataclasses import dataclass


def base64_url(b: bytes) -> str:
    """RFC 7636 base64url（无 padding）。"""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def new_device_id() -> str:
    """UUIDv4 字符串（OpenAI 把它存在 oai-did cookie 上）。"""
    return str(uuid.uuid4())


@dataclass(slots=True)
class PKCEPair:
    verifier: str
    challenge: str


def new_pkce() -> PKCEPair:
    """OpenAI auth0 SPA 标准 PKCE S256。

    注意：verifier 必须是 64 随机字节的 base64url 编码（不是 32），
    与 OpenAI 的 SDK 实现一致。32 字节会被 OpenAI /oauth/token 拒为
    invalid_code_challenge。
    """
    v = base64_url(random_bytes(64))
    digest = hashlib.sha256(v.encode("ascii")).digest()
    c = base64_url(digest)
    return PKCEPair(verifier=v, challenge=c)


def random_state_nonce() -> tuple[str, str]:
    """OAuth state + nonce 各 32 字节 → base64url。"""
    return base64_url(random_bytes(32)), base64_url(random_bytes(32))
