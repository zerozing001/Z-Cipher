"""ZPWD v1 教学模拟实现的异常与稳定错误码。"""

from __future__ import annotations

E_HEADER = "E_HEADER"
E_FORMAT = "E_FORMAT"
E_THRESHOLD = "E_THRESHOLD"
E_TOKEN = "E_TOKEN"
E_HASH = "E_HASH"
E_TAMPER = "E_TAMPER"
E_DECODE = "E_DECODE"
E_LOCKED = "E_LOCKED"
E_INPUT = "E_INPUT"
E_PSEUDO = "E_PSEUDO"

ALL_CODES = (
    E_HEADER, E_FORMAT, E_THRESHOLD, E_TOKEN, E_HASH,
    E_TAMPER, E_DECODE, E_LOCKED, E_INPUT, E_PSEUDO,
)


class ZCipherError(Exception):
    """所有 ZPWD 错误的基类，携带稳定错误码。"""

    def __init__(self, code: str, message: str = "", cause: "str | None" = None) -> None:
        self.code = code
        self.message = message or code
        self.cause = cause
        super().__init__("%s: %s" % (code, self.message))


class PseudoResponse(ZCipherError):
    """首次校验失败返回的伪响应：不泄露内部状态，只给出确定的伪明文。"""

    def __init__(self, cause: str, pseudo_plaintext: str) -> None:
        super().__init__(E_PSEUDO, "首次校验失败，返回伪响应", cause=cause)
        self.pseudo_plaintext = pseudo_plaintext
