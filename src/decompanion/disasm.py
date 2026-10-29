"""Disassembly in process (capstone, x86-32, details on). One shared decoder; the code walk uses capstone's
operand details directly. Memoised text listings for diffs come with the match milestone."""
from __future__ import annotations

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

__all__ = ["decoder", "X86_OP_IMM", "X86_OP_MEM", "X86_OP_REG", "X86_REG_INVALID", "CS_GRP_CALL", "CS_GRP_JUMP",
           "CS_GRP_RET"]

_md = None


def decoder() -> Cs:
    global _md
    if _md is None:
        _md = Cs(CS_ARCH_X86, CS_MODE_32)
        _md.detail = True
    return _md


def decode_one(data: bytes, va: int):
    """The first instruction of data at va, or None when the bytes do not decode."""
    return next(iter(decoder().disasm(data[:16], va, 1)), None)
