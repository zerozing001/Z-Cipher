"""HKDF-SHA256、子密钥派生、GF(256) 门限秘密共享与会话种子。"""

from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Dict, Iterable, Mapping

from .errors import E_INPUT, E_THRESHOLD, ZCipherError
from .prng import Stream
from .spec import (
    DEFAULT_N,
    DEFAULT_RULES,
    DEFAULT_T,
    KEY_BYTES,
    LABEL_KEYGEN,
    LABEL_SESSION,
    SUBKEY_LABELS,
)

_EXP = [0] * 512
_LOG = [0] * 256


def _xtime(a: int) -> int:
    """乘 2（GF(2^8)，模 x^8+x^4+x^3+x+1）。"""
    hi = a & 0x80
    a = (a << 1) & 0xFF
    if hi:
        a ^= 0x1B
    return a


def _mul_peasant(a: int, b: int) -> int:
    """俄罗斯农民乘法，作为建表的独立参考实现。"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _init_tables() -> None:
    # 0x02 在 AES 约简多项式下阶为 51，不是生成元；必须用 0x03 生成整张表。
    generator = 3
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _mul_peasant(x, generator)
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]
    if __debug__:
        assert len(set(_EXP[:255])) == 255, "GF(256) 指数表构造失败"
        assert x == 1, "GF(256) 乘法群阶不为 255"


_init_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) 零元素没有逆元")
    return _EXP[255 - _LOG[a]]


def _poly_eval(coeffs, x: int) -> int:
    y = 0
    for c in reversed(coeffs):
        y = gf_mul(y, x) ^ c
    return y


def shamir_split(secret: bytes, t: int, n: int, rng: Stream) -> Dict[int, bytes]:
    """把 secret 拆成 n 份，任意 t 份可重建；少于 t 份不泄露信息。"""
    if not (1 <= t <= n <= 255):
        raise ZCipherError(E_INPUT, "门限参数非法：需满足 1 <= t <= n <= 255")
    if t == 1:
        return {x: bytes(secret) for x in range(1, n + 1)}
    coeffs = [[secret[i]] + [rng.u8() for _ in range(t - 1)] for i in range(len(secret))]
    return {
        x: bytes(_poly_eval(coeffs[i], x) for i in range(len(secret)))
        for x in range(1, n + 1)
    }


def shamir_combine(shares: Mapping[int, bytes]) -> bytes:
    """用拉格朗日插值在 x=0 处重建秘密。"""
    if not shares:
        raise ZCipherError(E_THRESHOLD, "没有任何门限分量")
    xs = sorted(shares)
    if len(xs) == 1:
        return bytes(shares[xs[0]])
    lengths = {len(v) for v in shares.values()}
    if len(lengths) != 1:
        raise ZCipherError(E_INPUT, "所有门限分量必须等长")
    coefs = []
    for j, xj in enumerate(xs):
        num, den = 1, 1
        for m, xm in enumerate(xs):
            if m == j:
                continue
            num = gf_mul(num, xm)
            den = gf_mul(den, xj ^ xm)
        coefs.append(gf_mul(num, gf_inv(den)))
    size = len(shares[xs[0]])
    out = bytearray(size)
    for i in range(size):
        y = 0
        for j, xj in enumerate(xs):
            y ^= gf_mul(coefs[j], shares[xj][i])
        out[i] = y
    return bytes(out)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00", ikm, sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive(key: bytes, label: bytes, length: int = KEY_BYTES) -> bytes:
    return hkdf_expand(key, label, length)


def _verify_tables() -> None:
    if __debug__:
        for a in range(1, 256):
            if gf_mul(a, gf_inv(a)) != 1:
                raise RuntimeError("GF(256) 逆元自检失败")
        if _mul_peasant(0x57, 0x83) != gf_mul(0x57, 0x83):
            raise RuntimeError("GF(256) 乘法自检失败")


_verify_tables()


def session_seed(
    components: Mapping[int, bytes],
    threshold: int,
    dynamic_seed: bytes,
    rules: bytes = DEFAULT_RULES,
) -> bytes:
    """会话种子 = KDF(门限组合(暗码分量), 动态种子, 深码规则)。"""
    if threshold < 1:
        raise ZCipherError(E_INPUT, "门限必须 >= 1")
    if len(components) < threshold:
        raise ZCipherError(
            E_THRESHOLD,
            "暗码分量不足：需要 %d 份，当前 %d 份" % (threshold, len(components)),
        )
    use = sorted(components)[:threshold]
    combo = shamir_combine({x: components[x] for x in use})
    prk = hkdf_extract(dynamic_seed, combo + bytes(rules))
    return hkdf_expand(prk, LABEL_SESSION, KEY_BYTES)


def derive_subkeys(k_sess: bytes) -> Dict[str, bytes]:
    return {name: hkdf_expand(k_sess, label, KEY_BYTES) for name, label in SUBKEY_LABELS}


class KeyMaterial:
    """暗码分量集合 + 门限参数 + 深码规则。禁止把分量内容写入日志。"""

    def __init__(
        self,
        components: Mapping[int, bytes],
        threshold: int,
        n: "int | None" = None,
        rules: bytes = DEFAULT_RULES,
    ) -> None:
        if not components:
            raise ZCipherError(E_INPUT, "至少需要一个暗码分量")
        lengths = {len(v) for v in components.values()}
        if len(lengths) != 1 or not lengths or 0 in lengths:
            raise ZCipherError(E_INPUT, "所有暗码分量必须等长且非空")
        t = int(threshold)
        if t < 1 or t > len(components):
            raise ZCipherError(E_INPUT, "门限必须在 1..分量数 之间")
        self.components: Dict[int, bytes] = {int(k): bytes(v) for k, v in components.items()}
        self.threshold = t
        self.n = int(n) if n is not None else len(self.components)
        if self.n < t:
            raise ZCipherError(E_INPUT, "副本数必须 >= 门限")
        self.rules = bytes(rules)

    def fingerprint(self) -> bytes:
        h = sha256(b"ZPWD-v1/keymat")
        for x in sorted(self.components):
            h.update(bytes([x]))
            h.update(self.components[x])
        return h.digest()

    def __repr__(self) -> str:
        return "KeyMaterial(threshold=%d, n=%d, components=<%d 份已隐藏>)" % (
            self.threshold,
            self.n,
            len(self.components),
        )


def make_key_material(
    threshold: int = DEFAULT_T,
    n: int = DEFAULT_N,
    length: int = KEY_BYTES,
    seed: bytes = b"zpwd-demo",
) -> KeyMaterial:
    if not (1 <= threshold <= n <= 255):
        raise ZCipherError(E_INPUT, "门限参数非法")
    rng = Stream(LABEL_KEYGEN, seed)
    secret = rng.read(length)
    shares = shamir_split(secret, threshold, n, rng)
    return KeyMaterial(shares, threshold, n)
