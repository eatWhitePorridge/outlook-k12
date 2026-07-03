"""浏览器指纹元数据（UA / SecChUA / Locale）。

参考 newgpt2api browser/profile.go：Chrome 120-131 + Windows/macOS + 3 种 locale 池。
全部 happy path 注册都用同一份 Profile（一个 task 一份），保证 OpenAI 看到的
'用户' 在整条链路上一致。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

_CHROME_MAJORS: tuple[int, ...] = (120, 122, 124, 126, 128, 130, 131)
_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("Windows NT 10.0; Win64; x64", '"Windows"'),
    ("Macintosh; Intel Mac OS X 10_15_7", '"macOS"'),
)
_LOCALES: tuple[str, ...] = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8",
)


@dataclass(slots=True)
class Profile:
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_platform: str
    locale: str


def _rand_choice(seq):
    return seq[secrets.randbelow(len(seq))]


def random_profile() -> Profile:
    major = _rand_choice(_CHROME_MAJORS)
    ua_plat, sec_plat = _rand_choice(_PLATFORMS)
    build = 6000 + secrets.randbelow(900)
    patch = 100 + secrets.randbelow(200)
    user_agent = (
        f"Mozilla/5.0 ({ua_plat}) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.{build}.{patch} Safari/537.36"
    )
    sec_ch_ua = (
        f'"Not:A-Brand";v="99", "Google Chrome";v="{major}", "Chromium";v="{major}"'
    )
    return Profile(
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        sec_ch_ua_platform=sec_plat,
        locale=_rand_choice(_LOCALES),
    )
