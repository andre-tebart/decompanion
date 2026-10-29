"""x86-32 through capstone: the instruction-set plugin.

Flow kinds from capstone's groups: CALL for the call group, RET for the ret group, the jump group splits into
JUMP (`jmp` with an immediate target), CJUMP (every other jump with an immediate target: jcc, loop, jecxz)
and IJUMP (no immediate target: `jmp reg`, `jmp [mem]`).

Table shapes (TableShape) follow the switch code of the compilers of the era (VC6):
  `cmp r, N` ... [`mov(zx) r, byte [r + index table]`] ... `jmp dword [r*4 + table]`
The indirect jump reads a table when its memory operand has no base register, an index register and scale 4
(`table` = the displacement; entries are 4-byte code addresses). Scanning back over the instructions before it
in the same block (at most the 11 before it), the first `cmp reg, imm` with 0 <= imm < 0x400 bounds the table
to imm + 1 entries, and the first `mov` / `movzx` of a byte memory operand with a base or index register whose
displacement lies in the code range is the byte index table.

How it is computed (none of this changes a result):
- Every instruction is decoded once per rule run into a compact record (Ins). capstone's light decoder gives
  address, size, mnemonic and operand text; the full operand details are read only for an instruction whose
  text names a number inside the image (a memory operand or an immediate the walk records), a branch whose
  operand is not a plain number, and the first instruction of every mnemonic (its call / jump / ret group).
- The table shape reads the full details of the few `cmp` / `mov` / `movzx` before a table jump.
"""
from __future__ import annotations

import re

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

from . import register
from .base import CALL, CJUMP, IJUMP, JUMP, OTHER, RET, Decoder, Ins, Isa, TableShape

M32 = 0xffffffff
G_NONE, G_CALL, G_JUMP, G_RET = 0, 1, 2, 3
HEX = re.compile(r"0x([0-9a-f]+)")
NUMBER = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")

_md = None


def capstone() -> Cs:
    """The shared capstone instance (x86-32, details on)."""
    global _md
    if _md is None:
        _md = Cs(CS_ARCH_X86, CS_MODE_32)
        _md.detail = True
    return _md


def decode_one(data: bytes, va: int):
    """capstone's first instruction of data at va, or None when the bytes do not decode."""
    return next(iter(capstone().disasm(data[:16], va, 1)), None)


def _flow(group: int, mn: str, target) -> int:
    if group == G_CALL:
        return CALL
    if group == G_JUMP:
        if target is None:
            return IJUMP
        return JUMP if mn == "jmp" else CJUMP
    if group == G_RET:
        return RET
    return OTHER


class X86Decoder(Decoder):
    """Decodes the code range of an image into Ins records, memoised by address for one rule run."""

    def __init__(self, img, code_lo, code_hi, fill_forms):
        self.img = img
        self.lo, self.hi = code_lo, code_hi
        self.code = img.read(code_lo, code_hi - code_lo)
        self.md = capstone()
        self.fill_forms = frozenset(fill_forms)
        self.cache: dict[int, Ins] = {}
        self.groups: dict[str, int] = {}          # mnemonic -> group, from the first full decode of it
        self.ibase, self.iend = img.base, img.end

    def _in_image(self, v):
        return self.ibase <= v < self.iend

    def full(self, addr, size) -> Ins:
        """The record from capstone's operand details."""
        o = addr - self.lo
        ins = next(self.md.disasm(self.code[o:o + size], addr, 1))
        group = G_CALL if ins.group(CS_GRP_CALL) else G_JUMP if ins.group(CS_GRP_JUMP) else G_RET if ins.group(CS_GRP_RET) else G_NONE
        self.groups.setdefault(ins.mnemonic, group)
        ops = ins.operands
        target = ops[0].imm if group in (G_CALL, G_JUMP) and ops and ops[0].type == X86_OP_IMM else None
        mem = tuple((op.mem.disp & M32, op.size) for op in ops
                    if op.type == X86_OP_MEM and op.mem.disp and self._in_image(op.mem.disp & M32))
        imms = tuple(op.imm for op in ops if op.type == X86_OP_IMM)
        table = None
        if ins.mnemonic == "jmp" and ops and ops[0].type == X86_OP_MEM and ops[0].mem.base == X86_REG_INVALID \
                and ops[0].mem.index != X86_REG_INVALID and ops[0].mem.scale == 4:
            table = ops[0].mem.disp & M32
        return Ins(addr, ins.size, ins.mnemonic, _flow(group, ins.mnemonic, target), target, mem, imms, table,
                   bytes(ins.bytes) in self.fill_forms)

    def make(self, addr, size, mn, ops) -> Ins:
        group = self.groups.get(mn)
        if group is None:
            return self.full(addr, size)
        if group in (G_CALL, G_JUMP):
            if not NUMBER.match(ops):
                return self.full(addr, size)
            target = int(ops, 0)
        else:
            target = None
        for h in HEX.findall(ops):
            v = int(h, 16)
            if self._in_image(v) or self._in_image(-v & M32):
                return self.full(addr, size)
        o = addr - self.lo
        return Ins(addr, size, mn, _flow(group, mn, target), target, (), (), None, self.code[o:o + size] in self.fill_forms)

    def detail(self, addr):
        """capstone's full instruction at addr (for the few reads the records do not keep)."""
        o = addr - self.lo
        return next(self.md.disasm(self.code[o:o + 16], addr, 1))

    def decode(self, addr):
        cache, lo, hi = self.cache, self.lo, self.hi
        while lo <= addr < hi:
            ins = cache.get(addr)
            if ins is not None:
                yield ins
                addr = ins.addr + ins.size
                continue
            o = addr - lo
            got = False
            for a, size, mn, ops in self.md.disasm_lite(self.code[o:o + 0x400], addr):
                got = True
                ins = cache.get(a)
                if ins is None:
                    ins = cache[a] = self.make(a, size, mn, ops)
                yield ins
                addr = a + size
            if not got:
                return
            if addr < lo + o + 0x400 - 16:
                return

    def table_shape(self, jump, recent):
        bound = None
        byte_tbl = None
        for r in reversed(recent[:-1]):
            if r.mn not in ("cmp", "movzx", "mov"):
                continue
            ins = self.detail(r.addr)
            if ins.mnemonic == "cmp" and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM \
                    and ins.operands[0].type == X86_OP_REG and bound is None and 0 <= ins.operands[1].imm < 0x400:
                bound = ins.operands[1].imm + 1
            if ins.mnemonic in ("movzx", "mov") and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM \
                    and ins.operands[1].size == 1 and (ins.operands[1].mem.index != X86_REG_INVALID or ins.operands[1].mem.base != X86_REG_INVALID) \
                    and self.lo <= (ins.operands[1].mem.disp & M32) < self.hi and byte_tbl is None:
                byte_tbl = ins.operands[1].mem.disp & M32
        return TableShape(4, bound, byte_tbl, 1)

    def field_starts(self, ins):
        """A 4-byte immediate or displacement field after the first (opcode) byte: it starts at addr + 1 ..
        addr + size - 4."""
        return range(ins.addr + 1, ins.addr + ins.size - 3)


@register
class X86(Isa):
    key = "x86"
    ptr_size = 4
    byteorder = "little"

    def decoder(self, img, lo, hi, fill_forms):
        return X86Decoder(img, lo, hi, fill_forms)
