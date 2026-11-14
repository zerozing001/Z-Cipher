"""ZPWD v1 教学模拟规范：固定参数、域分离标签、多语言字符集表。

本模块是规范的唯一参数来源，其余模块不得自行硬编码魔数。
"""

from __future__ import annotations

MAGIC = "ZPWD1"
VERSION = 1
SEPARATOR = "."
CHIP_PREFIX = b"ZC"

BLOCK = 16
DEFAULT_T = 3
DEFAULT_N = 5
MAX_TEXT_BYTES = 1 << 16
KEY_BYTES = 32
TAG_BYTES = 16
NONCE_BYTES = 12
CHAIN_BYTES = 16
HEADER_BYTES = 2 + 1 + 1 + CHAIN_BYTES + 2

LABEL_SESSION = b"ZPWD-v1/session"
LABEL_STREAM = b"ZPWD-v1/stream"
LABEL_KEYGEN = b"ZPWD-v1/keygen"
LABEL_AEAD_ENC = b"ZPWD-v1/aead-enc"
LABEL_AEAD_MAC = b"ZPWD-v1/aead-mac"
LABEL_CHAIN = b"ZPWD-v1/chain"
LABEL_TOKEN = b"ZPWD-v1/token"
LABEL_NONCE = b"ZPWD-v1/nonce"
LABEL_SID = b"ZPWD-v1/sid"

SUBKEY_LABELS = (
    ("rotor", b"ZPWD-v1/rotor"),
    ("mask", b"ZPWD-v1/mask"),
    ("chaos", b"ZPWD-v1/chaos"),
    ("dual", b"ZPWD-v1/dual"),
    ("split", b"ZPWD-v1/split"),
    ("code", b"ZPWD-v1/code"),
    ("vm", b"ZPWD-v1/vm"),
    ("token", b"ZPWD-v1/token"),
    ("verify", b"ZPWD-v1/verify"),
    ("replica", b"ZPWD-v1/replica"),
)

DEFAULT_RULES = b"ZPWD-v1/deep-rules"

TABLES = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "αβγδεζηθικλμνξοπρστυφχψωΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ0123456789+-*/%=",
    "абвгдежзийклмнопрстуфхцчшщъыьэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
    "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿŒœ",
)

for _t in TABLES:
    assert len(_t) == 64, "字符集必须是 64 个字符"
    assert len(set(_t)) == 64, "字符集内不得有重复字符"
    assert SEPARATOR not in _t, "字符集不得包含分隔符"
del _t
