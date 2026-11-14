"""符号编码层、分形掩码层、混沌混合层，以及 PKCS#7 填充。"""

from __future__ import annotations

from .errors import E_DECODE, E_INPUT, ZCipherError
from .spec import BLOCK


def pad(data: bytes, block: int = BLOCK) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def unpad(data: bytes, block: int = BLOCK) -> bytes:
    if not data or len(data) % block != 0:
        raise ZCipherError(E_DECODE, "填充长度非法")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ZCipherError(E_DECODE, "填充校验失败")
    return data[:-n]


def _rol(b: int, s: int) -> int:
    return b if s == 0 else ((b << s) | (b >> (8 - s))) & 0xFF


def _ror(b: int, s: int) -> int:
    return b if s == 0 else ((b >> s) | (b << (8 - s))) & 0xFF


def _bit_perm(rng) -> list:
    p = list(range(BLOCK * 8))
    rng.shuffle(p)
    return p


def _bit_perm_inv(p: list) -> list:
    inv = [0] * len(p)
    for i, v in enumerate(p):
        inv[v] = i
    return inv


def _permute_bits(data: bytes, perm: list) -> bytes:
    if len(data) % BLOCK != 0:
        raise ZCipherError(E_INPUT, "位换块长度必须对齐")
    out = bytearray(len(data))
    for off in range(0, len(data), BLOCK):
        v = int.from_bytes(data[off:off + BLOCK], "big")
        w = 0
        for i in range(BLOCK * 8):
            w = (w << 1) | ((v >> (BLOCK * 8 - 1 - perm[i])) & 1)
        out[off:off + BLOCK] = w.to_bytes(BLOCK, "big")
    return bytes(out)


def _sboxes(rng, count: int = 8) -> list:
    boxes = []
    for _ in range(count):
        table = bytearray(range(256))
        rng.shuffle(table)
        boxes.append(bytes(table))
    return boxes


def _inverse(box: bytes) -> bytes:
    inv = bytearray(256)
    for i, v in enumerate(box):
        inv[v] = i
    return bytes(inv)


def symbol_encode(data: bytes, rng) -> bytes:
    """点划式位映射 -> 循环移位 -> 多表替换。"""
    perm = _bit_perm(rng)
    shift = rng.u8() % 8
    boxes = _sboxes(rng)
    out = _permute_bits(data, perm)
    out = bytes(_rol(b, shift) for b in out)
    return bytes(boxes[i % len(boxes)][b] for i, b in enumerate(out))


def symbol_decode(data: bytes, rng) -> bytes:
    perm = _bit_perm(rng)
    shift = rng.u8() % 8
    boxes = [_inverse(b) for b in _sboxes(rng)]
    out = bytes(boxes[i % len(boxes)][b] for i, b in enumerate(data))
    out = bytes(_ror(b, shift) for b in out)
    return _permute_bits(out, _bit_perm_inv(perm))


def fractal_mask(n: int, rng, threshold: int) -> bytes:
    """定点迭代系统生成与明文等长的伪随机掩码。"""
    if n < 0:
        raise ZCipherError(E_INPUT, "掩码长度非法")
    M = 1 << 32
    z = rng.u32() % (M - 2) + 1
    r = 4 * M - 1 - rng.u16() * 3
    out = bytearray(n)
    sh = threshold % 31
    for i in range(n * 8):
        z = (r * z * (M - z)) >> 64
        if z <= 0:
            z = 1
        elif z >= M:
            z = M - 1
        if (z >> sh) & 1:
            out[i >> 3] |= 0x80 >> (i & 7)
    return bytes(out)


def chaos_mix(data: bytes, mask: bytes, key_chaos: bytes) -> bytes:
    if len(data) != len(mask):
        raise ZCipherError(E_INPUT, "明文与掩码长度不一致")
    k = len(key_chaos)
    out = bytearray(len(data))
    for i in range(len(data)):
        p, m = data[i], mask[i]
        out[i] = (p + m + key_chaos[i % k]) & 0xFF if i & 1 else p ^ m
    return bytes(out)


def chaos_unmix(data: bytes, mask: bytes, key_chaos: bytes) -> bytes:
    if len(data) != len(mask):
        raise ZCipherError(E_INPUT, "密文与掩码长度不一致")
    k = len(key_chaos)
    out = bytearray(len(data))
    for i in range(len(data)):
        c, m = data[i], mask[i]
        out[i] = (c - m - key_chaos[i % k]) & 0xFF if i & 1 else c ^ m
    return bytes(out)
