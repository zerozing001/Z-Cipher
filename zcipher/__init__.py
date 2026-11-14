"""ZPWD v1 —— Z 密码教学模拟实现。

本包仅用于密码学协议教学与软件工程演练，不是经过密码学审查的
真实安全密码系统，不得用于实际保密通信。
"""

from __future__ import annotations

from .api import decode, encode, reset_state
from .errors import (
    ALL_CODES,
    E_DECODE,
    E_FORMAT,
    E_HASH,
    E_HEADER,
    E_INPUT,
    E_LOCKED,
    E_PSEUDO,
    E_TAMPER,
    E_THRESHOLD,
    E_TOKEN,
    PseudoResponse,
    ZCipherError,
)
from .kdf import KeyMaterial, make_key_material

__version__ = "1.0.0"
__all__ = [
    "decode",
    "encode",
    "reset_state",
    "KeyMaterial",
    "make_key_material",
    "ZCipherError",
    "PseudoResponse",
    "ALL_CODES",
    "E_HEADER",
    "E_FORMAT",
    "E_THRESHOLD",
    "E_TOKEN",
    "E_HASH",
    "E_TAMPER",
    "E_DECODE",
    "E_LOCKED",
    "E_INPUT",
    "E_PSEUDO",
]
