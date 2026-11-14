"""多语言字符集编码：把二进制码片映射为不同字符集的可打印文本。"""

from __future__ import annotations

from .errors import E_DECODE, ZCipherError
from .spec import TABLES


def encode(data: bytes, idx: int) -> str:
    table = TABLES[idx % len(TABLES)]
    buf = len(data).to_bytes(4, "big") + data
    nbits = len(buf) * 8
    npad = (-nbits) % 6
    total = (nbits + npad) // 6
    v = int.from_bytes(buf, "big") << npad
    return "".join(table[(v >> (6 * (total - 1 - i))) & 63] for i in range(total))


def decode(text: str, idx: int) -> bytes:
    table = TABLES[idx % len(TABLES)]
    rev = {ch: i for i, ch in enumerate(table)}
    v = 0
    for ch in text:
        if ch not in rev:
            raise ZCipherError(E_DECODE, "字符不在指定字符集内: %r" % ch)
        v = (v << 6) | rev[ch]
    nbits_total = 6 * len(text)
    npad = nbits_total % 8
    nbytes = nbits_total // 8
    if nbytes < 4:
        raise ZCipherError(E_DECODE, "码片长度不足")
    v >>= npad
    raw = v.to_bytes(nbytes, "big")
    ln = int.from_bytes(raw[:4], "big")
    if ln + 4 > nbytes:
        raise ZCipherError(E_DECODE, "码片长度字段越界")
    return raw[4:4 + ln]
