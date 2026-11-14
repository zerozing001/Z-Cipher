"""ZPWD v1 教学模拟实现的验收测试。

运行： python -X utf8 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zcipher import (  # noqa: E402
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
    KeyMaterial,
    PseudoResponse,
    ZCipherError,
    decode,
    encode,
    make_key_material,
    reset_state,
)
from zcipher.spec import TABLES  # noqa: E402


def default_km(t: int = 3, n: int = 5) -> KeyMaterial:
    return make_key_material(t, n, seed=b"test-seed")


def flip_chip(envelope: str, pos: int = 0, at: int = -1) -> str:
    """把第 pos 个码片的某个字符替换为同一字符集内的另一个字符。"""
    parts = envelope.split(".")
    chunk = parts[2 + pos]
    head, body = chunk[0], list(chunk[1:])
    table = TABLES[int(head) % len(TABLES)]
    idx = table.index(body[at])
    body[at] = table[(idx + 1) % len(table)]
    parts[2 + pos] = head + "".join(body)
    return ".".join(parts)


class TestRoundTrip(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.km = default_km()

    def test_mixed_text_roundtrip(self) -> None:
        cases = [
            "中文测试，标点符号！？",
            "Hello, World! 123",
            "混合 Mixed 文本 42 号 —— 全角（）【】",
            "single",
            "",
        ]
        for text in cases:
            with self.subTest(text=text):
                env = encode(text, self.km, seed=b"s1")
                self.assertEqual(decode(env, self.km), text)

    def test_same_seed_deterministic(self) -> None:
        a = encode("abc", self.km, seed=b"seed")
        b = encode("abc", self.km, seed=b"seed")
        self.assertEqual(a, b)

    def test_different_seed_differs(self) -> None:
        a = encode("abc", self.km, seed=b"seed-1")
        b = encode("abc", self.km, seed=b"seed-2")
        self.assertNotEqual(a, b)

    def test_envelope_shape(self) -> None:
        env = encode("shape", self.km, seed=b"s")
        parts = env.split(".")
        self.assertEqual(parts[0], "ZPWD1")
        self.assertEqual(len(parts), 2 + 5 + 1)
        for i in range(5):
            self.assertEqual(parts[2 + i][0], str(i))

    def test_threshold_any_subset(self) -> None:
        text = "门限子集"
        env = encode(text, self.km, seed=b"sub")
        comps = self.km.components
        for subset in ([1, 2, 3], [2, 3, 5], [1, 4, 5]):
            with self.subTest(subset=subset):
                reset_state()
                km = KeyMaterial({x: comps[x] for x in subset}, 3, n=5)
                self.assertEqual(decode(env, km), text)

    def test_short_text_boundary(self) -> None:
        for text in ["a", "ab", "abcdefghijklmnopq"]:
            with self.subTest(text=text):
                reset_state()
                env = encode(text, self.km, seed=b"b")
                self.assertEqual(decode(env, self.km), text)


class TestFailures(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.km = default_km()
        self.env = encode("tamper target", self.km, seed=b"f1")

    def test_tampered_chip(self) -> None:
        for pos in (0, 2, 4):
            with self.subTest(pos=pos):
                reset_state()
                bad = flip_chip(self.env, pos=pos)
                with self.assertRaises(ZCipherError) as ctx:
                    decode(bad, self.km, fail_mode="strict")
                self.assertIn(ctx.exception.code, (E_HASH, E_TAMPER, E_DECODE))

    def test_threshold_copies_insufficient(self) -> None:
        parts = self.env.split(".")
        bad = ".".join(parts[:4] + [parts[-1]])
        with self.assertRaises(ZCipherError) as ctx:
            decode(bad, self.km, fail_mode="strict")
        self.assertEqual(ctx.exception.code, E_THRESHOLD)

    def test_insufficient_components(self) -> None:
        comps = self.km.components
        weak = KeyMaterial({1: comps[1], 2: comps[2]}, 2)
        with self.assertRaises(ZCipherError) as ctx:
            decode(self.env, weak, fail_mode="strict")
        self.assertEqual(ctx.exception.code, E_THRESHOLD)

    def test_bad_token(self) -> None:
        parts = self.env.split(".")
        tok = list(parts[-1])
        tok[-1] = "A" if tok[-1] != "A" else "B"
        parts[-1] = "".join(tok)
        with self.assertRaises(ZCipherError) as ctx:
            decode(".".join(parts), self.km, fail_mode="strict")
        self.assertEqual(ctx.exception.code, E_TOKEN)

    def test_bad_header(self) -> None:
        bad = "ZPWD2" + self.env[len("ZPWD1"):]
        with self.assertRaises(ZCipherError) as ctx:
            decode(bad, self.km, fail_mode="strict")
        self.assertEqual(ctx.exception.code, E_HEADER)

    def test_chip_reorder(self) -> None:
        parts = self.env.split(".")
        parts[2], parts[3] = parts[3], parts[2]
        with self.assertRaises(ZCipherError) as ctx:
            decode(".".join(parts), self.km, fail_mode="strict")
        self.assertIn(ctx.exception.code, (E_FORMAT, E_HASH))

    def test_pseudo_then_lock(self) -> None:
        bad = flip_chip(self.env)
        with self.assertRaises(PseudoResponse) as first:
            decode(bad, self.km)
        self.assertEqual(first.exception.code, E_PSEUDO)
        self.assertIn(first.exception.cause, (E_HASH, E_TAMPER, E_DECODE))
        self.assertEqual(len(first.exception.pseudo_plaintext), 16)
        with self.assertRaises(ZCipherError) as second:
            decode(bad, self.km)
        self.assertEqual(second.exception.code, E_LOCKED)

    def test_lock_is_per_envelope(self) -> None:
        bad = flip_chip(self.env)
        with self.assertRaises(PseudoResponse):
            decode(bad, self.km)
        with self.assertRaises(ZCipherError):
            decode(bad, self.km)
        other = encode("another", self.km, seed=b"f2")
        self.assertEqual(decode(other, self.km), "another")


class TestInput(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()
        self.km = default_km()

    def test_encode_requires_str(self) -> None:
        with self.assertRaises(ZCipherError) as ctx:
            encode(b"bytes", self.km, seed=b"s")
        self.assertEqual(ctx.exception.code, E_INPUT)

    def test_decode_requires_str(self) -> None:
        with self.assertRaises(ZCipherError) as ctx:
            decode(123, self.km)
        self.assertEqual(ctx.exception.code, E_INPUT)

    def test_oversize_text(self) -> None:
        with self.assertRaises(ZCipherError) as ctx:
            encode("x" * 70000, self.km, seed=b"s")
        self.assertEqual(ctx.exception.code, E_INPUT)

    def test_bad_key_material(self) -> None:
        with self.assertRaises(ZCipherError) as ctx:
            encode("abc", "not-a-keymaterial", seed=b"s")
        self.assertEqual(ctx.exception.code, E_INPUT)


class TestLive(unittest.TestCase):
    def test_bidirectional(self) -> None:
        from zcipher.live import key_from_passphrase, translate

        reset_state()
        km = key_from_passphrase("demo-pass")
        env = translate("实时翻译 realtime", km, seed=b"s1")
        self.assertTrue(env.startswith("ZPWD1."))
        self.assertEqual(translate(env, km), "实时翻译 realtime")


class TestSpec(unittest.TestCase):
    def test_tables_are_64_unique(self) -> None:
        for table in TABLES:
            self.assertEqual(len(table), 64)
            self.assertEqual(len(set(table)), 64)
            self.assertNotIn(".", table)


if __name__ == "__main__":
    unittest.main(verbosity=2)
