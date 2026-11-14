"""双向翻译示例：自然语言 <-> Z 密码。"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zcipher import decode, encode, make_key_material  # noqa: E402


def main() -> int:
    km = make_key_material(threshold=3, n=5, seed=b"demo-seed")
    text = "Z密码 v1 教学模拟：Hello, 世界！123"
    env = encode(text, km, seed=b"dyn-001")
    print("[明文] %s" % text)
    print("[封装长度] %d" % len(env))
    print("[封装片段] %s" % env[:200])
    back = decode(env, km)
    print("[还原] %s" % back)
    print("[可逆] %s" % (back == text))
    env2 = encode(text, km, seed=b"dyn-002")
    print("[换 seed 后封装不同] %s" % (env2 != env))
    env3 = encode(text, km, seed=b"dyn-001")
    print("[同 seed 可复现] %s" % (env3 == env))
    return 0 if back == text else 1


if __name__ == "__main__":
    raise SystemExit(main())
