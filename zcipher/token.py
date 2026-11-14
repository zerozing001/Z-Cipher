"""过滤令牌、跨码片哈希链与恒定时间比较。"""

from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Iterable

from .errors import E_TOKEN, ZCipherError
from .spec import CHAIN_BYTES, LABEL_CHAIN, LABEL_TOKEN, TAG_BYTES


def genesis(sid: str) -> bytes:
    return sha256(LABEL_CHAIN + sid.encode("utf-8")).digest()[:CHAIN_BYTES]


def link(prev: bytes, raw: bytes) -> bytes:
    return sha256(prev + raw).digest()[:CHAIN_BYTES]


def make_token(k_token: bytes, raws: Iterable[bytes]) -> bytes:
    h = hmac.new(k_token, LABEL_TOKEN, sha256)
    for r in raws:
        h.update(len(r).to_bytes(4, "big"))
        h.update(r)
    return h.digest()[:TAG_BYTES]


def verify_token(k_token: bytes, raws: Iterable[bytes], tag: bytes) -> None:
    if not hmac.compare_digest(make_token(k_token, raws), tag):
        raise ZCipherError(E_TOKEN, "过滤令牌校验失败")
