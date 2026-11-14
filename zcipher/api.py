"""ZPWD v1 双向翻译接口：encode / decode 与失败状态机。"""

from __future__ import annotations

import base64
import json
import os
import unicodedata
from hashlib import sha256
from typing import Dict, List, Optional

from . import split as splitmod
from .aead import decrypt as aead_decrypt
from .aead import encrypt as aead_encrypt
from .charset import decode as charset_decode
from .charset import encode as charset_encode
from .errors import (
    E_DECODE,
    E_FORMAT,
    E_HASH,
    E_HEADER,
    E_INPUT,
    E_LOCKED,
    E_TAMPER,
    E_THRESHOLD,
    E_TOKEN,
    PseudoResponse,
    ZCipherError,
)
from .kdf import (
    KeyMaterial,
    derive,
    derive_subkeys,
    session_seed,
    shamir_combine,
    shamir_split,
)
from .layers import (
    chaos_mix,
    chaos_unmix,
    fractal_mask,
    pad,
    symbol_decode,
    symbol_encode,
    unpad,
)
from .prng import Stream
from .spec import (
    CHIP_PREFIX,
    HEADER_BYTES,
    LABEL_NONCE,
    LABEL_SID,
    MAGIC,
    MAX_TEXT_BYTES,
    NONCE_BYTES,
    SEPARATOR,
    TAG_BYTES,
    VERSION,
)
from .token import genesis, link, make_token, verify_token
from .vmcode import assemble as vm_assemble
from .vmcode import execute as vm_execute

_PSEUDO_CHARS = (
    "的世界密码学原理网络文字双向传播混沌分形门限秘密共享校验令牌虚拟机编码"
    "交换随机统计不可区分拆分配对真块假块副本分片字符集掩码混合派生种子"
)

_STATE: Dict[str, Dict[str, object]] = {}


def reset_state() -> None:
    """清空失败状态机记录（测试与演示用）。"""
    _STATE.clear()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad_len = (-len(text)) % 4
    try:
        return base64.urlsafe_b64decode(text + "=" * pad_len)
    except Exception:
        raise ZCipherError(E_FORMAT, "参数区不是合法的 base64url") from None


def _dynamic_seed(seed: "bytes | None") -> bytes:
    if seed is None:
        return os.urandom(16)
    if isinstance(seed, str):
        seed = seed.encode("utf-8")
    if not isinstance(seed, (bytes, bytearray)):
        raise ZCipherError(E_INPUT, "seed 必须是 bytes 或 str")
    return sha256(b"ZPWD-v1/dyn" + bytes(seed)).digest()[:16]


def _pseudo_plaintext(key_material: KeyMaterial, sid: str) -> str:
    h = sha256(key_material.fingerprint() + sid.encode("utf-8")).digest()
    return "".join(_PSEUDO_CHARS[h[i] % len(_PSEUDO_CHARS)] for i in range(16))


def _peek_sid(envelope: str) -> Optional[str]:
    try:
        parts = envelope.strip().split(SEPARATOR)
        if len(parts) < 3 or parts[0] != MAGIC:
            return None
        param = json.loads(_b64d(parts[1]))
        sid = param.get("sid")
        return sid if isinstance(sid, str) else None
    except Exception:
        return None


def encode(text: str, key_material: KeyMaterial, seed: "bytes | None" = None) -> str:
    """自然语言 -> Z 密码密文封装。"""
    if not isinstance(text, str):
        raise ZCipherError(E_INPUT, "明文必须是 str")
    if not isinstance(key_material, KeyMaterial):
        raise ZCipherError(E_INPUT, "key_material 必须是 KeyMaterial")
    plain = unicodedata.normalize("NFC", text).encode("utf-8")
    if len(plain) > MAX_TEXT_BYTES:
        raise ZCipherError(E_INPUT, "明文超过单条上限")

    q = _dynamic_seed(seed)
    k_sess = session_seed(key_material.components, key_material.threshold, q, key_material.rules)
    sk = derive_subkeys(k_sess)
    sid = sha256(LABEL_SID + q).hexdigest()[:16]
    t = key_material.threshold
    n = key_material.n

    body = pad(plain)
    body = symbol_encode(body, Stream(sk["rotor"], b"symbol"))
    mask = fractal_mask(len(body), Stream(sk["mask"], b"mask"), sk["mask"][0])
    body = chaos_mix(body, mask, sk["chaos"])

    nonce = derive(sk["dual"], LABEL_NONCE, NONCE_BYTES)
    ct, tag = aead_encrypt(sk["dual"], nonce, body, sid.encode("utf-8"))
    core = ct + tag

    shares = shamir_split(core, t, n, Stream(sk["replica"], b"replica"))

    chips: List[str] = []
    raws: List[bytes] = []
    prev = genesis(sid)
    for pos in range(n):
        x = pos + 1
        share = shares[x]
        body_bytes = splitmod.pack(share, Stream(sk["split"], b"chip-%d" % x))
        prog = vm_assemble(body_bytes, Stream(sk["vm"], b"vm-%d" % x))
        raw = (
            CHIP_PREFIX
            + bytes([x, n])
            + prev
            + len(share).to_bytes(2, "big")
            + prog
        )
        raws.append(raw)
        chips.append(str(pos) + charset_encode(raw, pos))
        prev = link(prev, raw)

    tok = make_token(sk["token"], raws)
    param = {"v": VERSION, "t": t, "n": n, "q": q.hex(), "sid": sid, "h": prev.hex()}
    param_b64 = _b64u(json.dumps(param, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return SEPARATOR.join([MAGIC, param_b64] + chips + [_b64u(tok)])


def _parse_chip(raw: bytes, pos: int) -> Dict[str, object]:
    if len(raw) < HEADER_BYTES:
        raise ZCipherError(E_FORMAT, "码片长度不足")
    if raw[:2] != CHIP_PREFIX:
        raise ZCipherError(E_FORMAT, "码片魔数不匹配")
    return {
        "x": raw[2],
        "n": raw[3],
        "prev": raw[4:4 + 16],
        "share_len": int.from_bytes(raw[20:22], "big"),
        "prog": raw[22:],
        "raw": raw,
        "pos": pos,
    }


def _decode_impl(envelope: str, key_material: KeyMaterial) -> str:
    parts = envelope.strip().split(SEPARATOR)
    if not parts or parts[0] != MAGIC:
        raise ZCipherError(E_HEADER, "协议头不匹配，期望 %s" % MAGIC)
    if len(parts) < 4:
        raise ZCipherError(E_FORMAT, "封装结构不完整")

    try:
        param = json.loads(_b64d(parts[1]))
    except ZCipherError:
        raise
    except Exception:
        raise ZCipherError(E_FORMAT, "参数区不是合法 JSON") from None
    if not isinstance(param, dict):
        raise ZCipherError(E_FORMAT, "参数区结构非法")

    if int(param.get("v", -1)) != VERSION:
        raise ZCipherError(E_HEADER, "不支持的协议版本")
    t = int(param.get("t", 0))
    n = int(param.get("n", 0))
    if not (1 <= t <= n <= 255):
        raise ZCipherError(E_FORMAT, "门限参数非法")
    sid = str(param.get("sid", ""))
    if len(sid) != 16:
        raise ZCipherError(E_FORMAT, "会话标识非法")
    try:
        q = bytes.fromhex(str(param.get("q", "")))
    except ValueError:
        raise ZCipherError(E_FORMAT, "动态种子不是合法十六进制") from None
    if len(q) != 16:
        raise ZCipherError(E_FORMAT, "动态种子长度非法")

    anchor_hex = param.get("h")
    if not isinstance(anchor_hex, str) or len(anchor_hex) != 32:
        raise ZCipherError(E_FORMAT, "哈希链锚点非法")
    try:
        anchor = bytes.fromhex(anchor_hex)
    except ValueError:
        raise ZCipherError(E_FORMAT, "哈希链锚点不是合法十六进制") from None

    chip_texts = parts[2:-1]
    token_bytes = _b64d(parts[-1])
    if len(chip_texts) < t:
        raise ZCipherError(
            E_THRESHOLD, "副本不足：需要 %d 份，当前 %d 份" % (t, len(chip_texts))
        )

    k_sess = session_seed(key_material.components, t, q, key_material.rules)
    sk = derive_subkeys(k_sess)

    chips: List[Dict[str, object]] = []
    for pos, text in enumerate(chip_texts):
        if len(text) < 2:
            raise ZCipherError(E_FORMAT, "码片文本过短")
        head = text[0]
        if not head.isdigit():
            raise ZCipherError(E_FORMAT, "码片缺少位次前缀")
        if int(head) != pos:
            raise ZCipherError(E_FORMAT, "码片位次与顺序不一致")
        raw = charset_decode(text[1:], pos)
        chips.append(_parse_chip(raw, pos))

    chips.sort(key=lambda c: int(c["x"]))

    prev = genesis(sid)
    run = 0
    for chip in chips:
        if int(chip["x"]) != run + 1:
            break
        if chip["prev"] != prev:
            raise ZCipherError(E_HASH, "哈希链断裂，码片可能被篡改或重排")
        prev = link(prev, chip["raw"])  # type: ignore[arg-type]
        run += 1
    if run < t:
        raise ZCipherError(
            E_THRESHOLD, "连续副本不足：需要 %d 段哈希链，当前 %d 段" % (t, run)
        )
    if prev != anchor:
        raise ZCipherError(E_HASH, "哈希链锚点不匹配：末段码片缺失或被篡改")

    verify_token(sk["token"], [c["raw"] for c in chips], token_bytes)  # type: ignore[misc]

    shares: Dict[int, bytes] = {}
    for chip in chips[:t]:
        x = int(chip["x"])
        body = vm_execute(chip["prog"])  # type: ignore[arg-type]
        shares[x] = splitmod.unpack(
            body, int(chip["share_len"]), Stream(sk["split"], b"chip-%d" % x)
        )

    core = shamir_combine(shares)
    if len(core) <= TAG_BYTES:
        raise ZCipherError(E_FORMAT, "密文核长度非法")
    ct, tag = core[:-TAG_BYTES], core[-TAG_BYTES:]
    nonce = derive(sk["dual"], LABEL_NONCE, NONCE_BYTES)
    body = aead_decrypt(sk["dual"], nonce, ct, tag, sid.encode("utf-8"))

    mask = fractal_mask(len(body), Stream(sk["mask"], b"mask"), sk["mask"][0])
    body = chaos_unmix(body, mask, sk["chaos"])
    body = symbol_decode(body, Stream(sk["rotor"], b"symbol"))
    plain = unpad(body)
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        raise ZCipherError(E_DECODE, "还原结果不是合法 UTF-8") from None
    return unicodedata.normalize("NFC", text)


def decode(
    envelope: str,
    key_material: KeyMaterial,
    fail_mode: str = "pseudo",
) -> str:
    """Z 密码密文封装 -> 自然语言。

    fail_mode="pseudo" 时，首次校验失败返回伪响应异常 PseudoResponse，
    第二次失败锁定该密文会话并返回 E_LOCKED；
    fail_mode="strict" 时直接抛出原始错误码。
    """
    if not isinstance(envelope, str):
        raise ZCipherError(E_INPUT, "密文封装必须是 str")
    if not isinstance(key_material, KeyMaterial):
        raise ZCipherError(E_INPUT, "key_material 必须是 KeyMaterial")
    if fail_mode not in ("pseudo", "strict"):
        raise ZCipherError(E_INPUT, "fail_mode 只能是 pseudo 或 strict")

    sid = _peek_sid(envelope)
    state_key = sid or "<unparsed>"
    state = _STATE.setdefault(state_key, {"fails": 0, "locked": False})
    if state["locked"]:
        raise ZCipherError(E_LOCKED, "该密文会话已锁定，拒绝后续解密请求")

    try:
        return _decode_impl(envelope, key_material)
    except ZCipherError as exc:
        state["fails"] = int(state["fails"]) + 1
        locked_now = int(state["fails"]) >= 2
        if locked_now:
            state["locked"] = True
        if fail_mode == "strict":
            raise
        if locked_now:
            raise ZCipherError(E_LOCKED, "该密文会话已锁定，拒绝后续解密请求") from None
        if exc.code in (E_TOKEN, E_HASH, E_TAMPER, E_DECODE):
            raise PseudoResponse(exc.code, _pseudo_plaintext(key_material, state_key)) from None
        raise
