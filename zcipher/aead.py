"""二度加密层：HMAC-SHA256 计数器模式 + encrypt-then-MAC（教学替代 AEAD）。"""

from __future__ import annotations

import hmac
from hashlib import sha256

from .errors import E_TAMPER, ZCipherError
from .spec import LABEL_AEAD_ENC, LABEL_AEAD_MAC, TAG_BYTES


def _keys(k_dual: bytes):
    return (
        hmac.new(k_dual, LABEL_AEAD_ENC, sha256).digest(),
        hmac.new(k_dual, LABEL_AEAD_MAC, sha256).digest(),
    )


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(4, "big"), sha256).digest()
        ctr += 1
    return bytes(out[:n])


def _tag(key_mac: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    return hmac.new(key_mac, nonce + aad + ct, sha256).digest()[:TAG_BYTES]


def encrypt(k_dual: bytes, nonce: bytes, plaintext: bytes, aad: bytes):
    key_enc, key_mac = _keys(k_dual)
    ks = _keystream(key_enc, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    return ct, _tag(key_mac, nonce, aad, ct)


def decrypt(k_dual: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes) -> bytes:
    key_enc, key_mac = _keys(k_dual)
    if not hmac.compare_digest(_tag(key_mac, nonce, aad, ct), tag):
        raise ZCipherError(E_TAMPER, "二度加密认证标签校验失败")
    ks = _keystream(key_enc, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))
