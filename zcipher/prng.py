"""确定性字节流：HMAC-SHA256 计数器模式（教学替代 CSPRNG）。

原则：所有随机过程都从 seed 派生，同一 seed 下严格可复现。
"""

from __future__ import annotations

import hmac
from hashlib import sha256
from typing import List, MutableSequence

from .spec import LABEL_STREAM


class Stream:
    """由密钥与标签派生的确定性伪随机字节流。"""

    def __init__(self, key: bytes, label: bytes = b"") -> None:
        self._key = hmac.new(key, LABEL_STREAM + label, sha256).digest()
        self._ctr = 0
        self._buf = b""

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be >= 0")
        while len(self._buf) < n:
            block = hmac.new(self._key, self._ctr.to_bytes(8, "big"), sha256).digest()
            self._buf += block
            self._ctr += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.read(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "big")

    def below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be > 0")
        if n == 1:
            return 0
        limit = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.u32()
            if v < limit:
                return v % n

    def shuffle(self, seq: MutableSequence) -> MutableSequence:
        for i in range(len(seq) - 1, 0, -1):
            j = self.below(i + 1)
            seq[i], seq[j] = seq[j], seq[i]
        return seq
