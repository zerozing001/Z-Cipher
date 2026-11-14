"""虚拟机式指令编码与混淆：数据被表示为带花指令的私有指令流。"""

from __future__ import annotations

from .errors import E_DECODE, ZCipherError

OP_NOP = 0x00
OP_DATA = 0x01
OP_JUNK = 0x02
OP_HALT = 0xFF


def assemble(payload: bytes, rng) -> bytes:
    """把字节串编译成指令流，随机插入无效分支与空操作。"""
    out = bytearray()
    pos = 0
    total = len(payload)
    while pos < total:
        ln = min(1 + rng.below(31), total - pos)
        out.append(OP_DATA)
        out += ln.to_bytes(2, "big")
        out += payload[pos:pos + ln]
        pos += ln
        if rng.below(2) == 0:
            jl = 1 + rng.below(24)
            out.append(OP_JUNK)
            out += jl.to_bytes(2, "big")
            out += rng.read(jl)
        if rng.below(3) == 0:
            out.append(OP_NOP)
    out.append(OP_HALT)
    return bytes(out)


def execute(prog: bytes) -> bytes:
    """解释执行指令流：只拼接 DATA 块，丢弃花指令。"""
    out = bytearray()
    i = 0
    n = len(prog)
    halted = False
    while i < n:
        op = prog[i]
        i += 1
        if op == OP_HALT:
            halted = True
            break
        if op == OP_NOP:
            continue
        if op in (OP_DATA, OP_JUNK):
            if i + 2 > n:
                raise ZCipherError(E_DECODE, "指令长度字段截断")
            ln = int.from_bytes(prog[i:i + 2], "big")
            i += 2
            if i + ln > n:
                raise ZCipherError(E_DECODE, "指令操作数截断")
            if op == OP_DATA:
                out += prog[i:i + ln]
            i += ln
            continue
        raise ZCipherError(E_DECODE, "未知操作码 0x%02x" % op)
    if not halted:
        raise ZCipherError(E_DECODE, "指令流缺少停机指令")
    return bytes(out)
