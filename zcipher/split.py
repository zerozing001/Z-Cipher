"""三次拆分、随机配对、真假块混合与门限副本包装。"""

from __future__ import annotations

from .errors import E_DECODE, ZCipherError

BLOCK = 16


def _perms(rng, rounds: int = 3) -> list:
    out = []
    for _ in range(rounds):
        p = [0, 1, 2]
        rng.shuffle(p)
        out.append(p)
    return out


def _bounds(length: int) -> list:
    a = length // 3
    b = (length - a) // 2
    return [a, b, length - a - b]


def triple_split(data: bytes, rng) -> bytes:
    if len(data) < 6:
        return data
    cur = data
    for p in _perms(rng):
        bd = _bounds(len(cur))
        segs = [cur[:bd[0]], cur[bd[0]:bd[0] + bd[1]], cur[bd[0] + bd[1]:]]
        cur = segs[p[0]] + segs[p[1]] + segs[p[2]]
    return cur


def triple_join(data: bytes, rng) -> bytes:
    if len(data) < 6:
        return data
    cur = data
    for p in reversed(_perms(rng)):
        bd = _bounds(len(cur))
        lens = [bd[p[0]], bd[p[1]], bd[p[2]]]
        segs = [b"", b"", b""]
        pos = 0
        for i in range(3):
            segs[p[i]] = cur[pos:pos + lens[i]]
            pos += lens[i]
        cur = segs[0] + segs[1] + segs[2]
    return cur


def _plan(rng, nblocks: int) -> list:
    order = list(range(nblocks))
    rng.shuffle(order)
    slots = []
    for k in order:
        slots.append(("r", k))
        if rng.below(2) == 0:
            slots.append(("j", 1 + rng.below(24)))
    return slots


def pack(secret: bytes, rng) -> bytes:
    nblocks = (len(secret) + BLOCK - 1) // BLOCK
    slots = _plan(rng, nblocks)
    body = triple_split(secret, rng)
    padded = body + b"\x00" * (nblocks * BLOCK - len(body))
    out = bytearray()
    for kind, v in slots:
        if kind == "r":
            out += padded[v * BLOCK:(v + 1) * BLOCK]
        else:
            out += rng.read(v)
    return bytes(out)


def unpack(blob: bytes, secret_len: int, rng) -> bytes:
    nblocks = (secret_len + BLOCK - 1) // BLOCK
    slots = _plan(rng, nblocks)
    buf = bytearray(nblocks * BLOCK)
    pos = 0
    for kind, v in slots:
        if kind == "r":
            if pos + BLOCK > len(blob):
                raise ZCipherError(E_DECODE, "码片长度不足，无法取出真分片")
            buf[v * BLOCK:(v + 1) * BLOCK] = blob[pos:pos + BLOCK]
            pos += BLOCK
        else:
            pos += v
    return triple_join(bytes(buf[:secret_len]), rng)
