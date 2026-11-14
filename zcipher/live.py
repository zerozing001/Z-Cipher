"""Z 密码实时双向翻译（教学模拟）。

逐行即时翻译：输入自然语言立刻得到 Z 密码封装，输入封装立刻还原明文。

用法：
    python -m zcipher.live --key 你的口令
    python -m zcipher.live --key 你的口令 --text "要翻译的一句话"
    python -m zcipher.live --key 你的口令 --stdin < input.txt
"""

from __future__ import annotations

import argparse
import os
import sys

from .api import decode, encode
from .errors import PseudoResponse, ZCipherError
from .kdf import KeyMaterial, make_key_material
from .spec import MAGIC, SEPARATOR

BANNER = (
    "Z 密码 v1 实时双向翻译（教学模拟，非真实加密）\r\n"
    "  自然语言 -> 输出 Z 密码封装\r\n"
    "  ZPWD1. 开头的封装 -> 输出明文\r\n"
    "  quit / exit / Ctrl+Z 回车 退出"
)
PROMPT = "zcipher> "

ENV_KEY = "ZCIPHER_KEY"


def key_from_passphrase(passphrase: str, t: int = 3, n: int = 5) -> KeyMaterial:
    """由口令派生一整套教学用暗码分量（任意 t 份可重建）。"""
    return make_key_material(threshold=t, n=n, seed=passphrase.encode("utf-8"))


def is_envelope(line: str) -> bool:
    return line.startswith(MAGIC + SEPARATOR)


def translate(
    line: str,
    key_material: KeyMaterial,
    seed: "bytes | None" = None,
    fail_mode: str = "strict",
) -> str:
    if is_envelope(line):
        return decode(line, key_material, fail_mode=fail_mode)
    return encode(line, key_material, seed=seed)


def _emit(text: str) -> None:
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:
        sys.stdout.buffer.write((text + "\n").encode("utf-8"))
    sys.stdout.flush()


def _handle(line: str, km: KeyMaterial, seed: "bytes | None", fail_mode: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        _emit(translate(line, km, seed=seed, fail_mode=fail_mode))
    except PseudoResponse as exc:
        _emit("[伪响应 %s] %s" % (exc.cause, exc.pseudo_plaintext))
    except ZCipherError as exc:
        _emit("[%s] %s" % (exc.code, exc.message))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m zcipher.live",
        description="Z 密码 v1 实时双向翻译（教学模拟，非真实加密）",
    )
    p.add_argument(
        "--key",
        default=os.environ.get(ENV_KEY),
        help="口令，用于派生教学用暗码分量；也可用环境变量 %s" % ENV_KEY,
    )
    p.add_argument("--threshold", type=int, default=3, help="门限，默认 3")
    p.add_argument("--copies", type=int, default=5, help="副本数，默认 5")
    p.add_argument("--seed", default=None, help="固定动态种子（可复现输出）")
    p.add_argument("--text", default=None, help="非交互：翻译一行后退出")
    p.add_argument("--stdin", action="store_true", help="逐行读取标准输入后退出")
    p.add_argument(
        "--pseudo",
        action="store_true",
        help="启用失败状态机（首次伪响应，再次锁定），默认 strict",
    )
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.key:
        parser.error("缺少 --key（或设置环境变量 %s）" % ENV_KEY)
    if not (1 <= args.threshold <= args.copies <= 255):
        parser.error("门限参数非法：需 1 <= threshold <= copies <= 255")

    km = key_from_passphrase(args.key, args.threshold, args.copies)
    seed = args.seed.encode("utf-8") if args.seed else None
    mode = "pseudo" if args.pseudo else "strict"

    if args.text is not None:
        _handle(args.text, km, seed, mode)
        return 0

    if args.stdin:
        for line in sys.stdin:
            if line.strip() in ("quit", "exit"):
                break
            _handle(line, km, seed, mode)
        return 0

    _emit(BANNER)
    while True:
        try:
            line = input(PROMPT)
        except EOFError:
            break
        except KeyboardInterrupt:
            _emit("")
            break
        if line.strip() in ("quit", "exit", ":q"):
            break
        _handle(line, km, seed, mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
