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

import collections
import itertools
import re

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

from . import register
from .base import CALL, CJUMP, IJUMP, JUMP, OTHER, RET, Decoder, Ins, Isa, Line, TableShape

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


# ------------------------------------------------------------------------------------------------ the instruction diff
# Ported from the first attempt's decomp/match/diffclass.py and ledger/grade.py (one_renaming), from objdump's
# spelling to capstone's (`mov eax, dword ptr [esp + 4]`, scale-1 index without `*1`).
GPR_ALL = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]     # ebp counts only in functions without a frame pointer
SUB = {"eax": ["ax", "al", "ah"], "ebx": ["bx", "bl", "bh"], "ecx": ["cx", "cl", "ch"], "edx": ["dx", "dl", "dh"],
       "esi": ["si"], "edi": ["di"], "ebp": ["bp"]}
REG_RE = re.compile(r"\b(e[abcd]x|e[sd]i|ebp|[abcd][xlh]|[sd]i|bp)\b")
NUM = r"(?:0x[0-9a-f]+|\d+)"
SLOT_RE = re.compile(r"\[(esp|ebp)((?: [+-] " + NUM + r")?)\]")
SIB_RE = re.compile(r"\[(e[abcd]x|e[sd]i|ebp) \+ (e[abcd]x|e[sd]i|ebp)((?: [+-] " + NUM + r")?)\]")
TOKEN_RE = re.compile(r"\[(?:esp|ebp)(?: [+-] " + NUM + r")?\]|\b(?:e[abcd]x|e[sd]i|ebp|[abcd][xlh]|[sd]i|bp)\b")
HEXNUM = re.compile(r"0x[0-9a-f]+")
FRAME = "mov ebp, esp"

_lite = None


def capstone_lite() -> Cs:
    """A capstone instance without operand details (text only)."""
    global _lite
    if _lite is None:
        _lite = Cs(CS_ARCH_X86, CS_MODE_32)
    return _lite


def full_reg(r):
    for big, subs in SUB.items():
        if r == big or r in subs:
            return big
    return r


def rename_regs(lines, mapping):
    sub = {}
    for k, v in mapping.items():
        sub[k] = v
        for sk, sv in zip(SUB[k], SUB[v]):
            if len(SUB[k]) == len(SUB[v]):
                sub[sk] = sv
    return [REG_RE.sub(lambda m: sub.get(m[1], m[1]), t) for t in lines]


def rename_slots(lines, mapping):
    return [SLOT_RE.sub(lambda m: "[" + m[1] + mapping.get(m[2], m[2]) + "]", t) for t in lines]


ESP_RE = re.compile(r"\[esp((?: [+-] " + NUM + r")?)\]")
ESP_ADJ = re.compile(r"^(sub|add) esp, (" + NUM + r")$")


def frame_size(lines) -> int | None:
    """The frame a prologue allocates: the first `sub esp, N` among the first 8 instructions."""
    for t in lines[:8]:
        m = ESP_ADJ.match(t)
        if m and m[1] == "sub":
            return int(m[2], 0)
    return None


def slot_value(m) -> int:
    """The signed offset of a SLOT_RE match (`[esp + 0x10]` 16, `[ebp - 8]` -8, `[esp]` 0)."""
    s = m[2].replace(" ", "")
    return int(s, 0) if s else 0


def esp_normalised(lines):
    """The lines with every `[esp + N]` rewritten to the offset it had at the first line (the bytes pushed by
    `push` / `sub esp, N` before it are subtracted, `pop` / `add esp, N` added back): the same stack slot reads
    the same on both sides of a hunk whose stores moved across a push. A `call` leaves esp as it was."""
    out, delta = [], 0

    def fix(m):
        v = int(m[1].replace(" ", ""), 0) if m[1] else 0
        v -= delta
        return "[esp]" if v == 0 else (f"[esp + {hex(v)}]" if v > 0 else f"[esp - {hex(-v)}]")

    for t in lines:
        out.append(ESP_RE.sub(fix, t))
        mn = t.split(" ", 1)[0]
        a = ESP_ADJ.match(t)
        if mn in ("push", "pushfd"):
            delta += 4
        elif mn in ("pop", "popfd"):
            delta -= 4
        elif a:
            delta += int(a[2], 0) * (1 if a[1] == "sub" else -1)
    return out


def find_map(xa, xb, regex, norm, rename, gpr, limit=6):
    """A token renaming that makes xa equal to xb, or None."""
    if len(xa) != len(xb):
        return None
    toks = sorted({norm(m) for t in xa + xb for m in regex.finditer(t)})
    if regex is REG_RE:
        toks = [t for t in toks if t in gpr]
    if len(toks) > limit:
        return None
    for perm in itertools.permutations(toks):
        mapping = {k: v for k, v in zip(toks, perm) if k != v}
        if mapping and rename(xa, mapping) == xb:
            return mapping
    return None


def swap_sib(t):
    return SIB_RE.sub(lambda m: "[" + m[2] + " + " + m[1] + (m[3] or "") + "]", t)


def sib_explain(xa, xb):
    if len(xa) != len(xb):
        return None
    changed = False
    for x, y in zip(xa, xb):
        if x == y:
            continue
        s = swap_sib(x)
        if s == x or s != y:
            return None
        changed = True
    return "base/index swapped in [r1 + r2 + disp]" if changed else None


def gpr_for(a: list[str]) -> list[str]:
    """The registers a renaming may touch in this function: ebp only without a frame pointer."""
    return [r for r in GPR_ALL if r != "ebp"] if FRAME in a[:4] else list(GPR_ALL)


@register
class X86(Isa):
    key = "x86"
    ptr_size = 4
    byteorder = "little"

    def decoder(self, img, lo, hi, fill_forms):
        return X86Decoder(img, lo, hi, fill_forms)

    def listing(self, code, va, mask, image_range, fill_forms):
        """capstone's Intel text, spaces normalised; masked fields hold the image's first address (an absolute
        field reads X; a relative one's target is replaced by X), and every number inside the image reads X.
        A jump with an immediate target outside the masked fields keeps the target in Line.target."""
        lo, hi = image_range
        data = bytearray(code)
        dummy = lo.to_bytes(4, "little")
        runs = []
        if mask is not None:
            k = 0
            while k < len(mask):
                if mask[k]:
                    e = k
                    while e < len(mask) and mask[e]:
                        e += 1
                    for j in range(k, e):
                        data[j] = dummy[(j - k) % 4]
                    runs.append((k, e))
                    k = e
                else:
                    k += 1
        fills = frozenset(fill_forms)
        out = []
        for a, size, mn, ops in capstone_lite().disasm_lite(bytes(data), va):
            text = (mn + " " + ops).strip() if ops else mn
            text = re.sub(r"\s+", " ", text)
            masked = set()
            o = a - va
            for s, e in runs:
                if s < o + size and o < e:
                    masked.add(lo)
                    masked.add((a + size + lo) & M32)
            def num(m, masked=masked):
                v = int(m.group(0), 16)
                return "X" if v in masked or lo <= v < hi else m.group(0)
            target = int(ops, 0) if not masked and mn.startswith(("j", "loop")) and NUMBER.match(ops) else None
            text = HEXNUM.sub(num, text)
            out.append(Line(a, size, text, bytes(code[o:o + size]) in fills, target))
        return out

    def disasm(self, code, va, fill_forms=()):
        """capstone's Intel text, unchanged."""
        fills = frozenset(fill_forms)
        out = []
        for a, size, mn, ops in capstone_lite().disasm_lite(bytes(code), va):
            o = a - va
            out.append(Line(a, size, (mn + " " + ops).strip() if ops else mn, bytes(code[o:o + size]) in fills))
        return out

    def numbers(self, text):
        """capstone writes every number from 10 on in hex (`0x...`)."""
        return [(m.start(), m.end(), int(m.group(1), 16)) for m in HEX.finditer(text)]

    def explain(self, xa, xb, context):
        gpr = gpr_for(context)
        m = find_map(xa, xb, REG_RE, lambda m: full_reg(m[1]), rename_regs, gpr)
        if m:
            return "regs", " ".join(f"{k}->{v}" for k, v in m.items())
        toks = sorted({full_reg(mm[1]) for t in xa + xb for mm in REG_RE.finditer(t)} & set(gpr))
        if len(xa) == len(xb) and len(toks) <= 6:
            for perm in itertools.permutations(toks):
                rm = {k: v for k, v in zip(toks, perm) if k != v}
                ra = rename_regs(xa, rm) if rm else xa
                sm = find_map(ra, xb, SLOT_RE, lambda mm: mm[2], rename_slots, gpr, 5)
                if sm:
                    desc = " ".join(f"{k}->{v}" for k, v in rm.items())
                    return "slots", (desc + " " if desc else "") + " ".join(f"[{k or '+0'}]->[{v or '+0'}]" for k, v in sm.items())
            for perm in itertools.permutations(toks):
                rm = {k: v for k, v in zip(toks, perm) if k != v}
                if rm and collections.Counter(rename_regs(xa, rm)) == collections.Counter(xb):
                    return "order", "same instructions, other order, after " + " ".join(f"{k}->{v}" for k, v in rm.items())
        if len(xa) == len(xb) and any(t.split(" ", 1)[0] in ("push", "pop") or ESP_ADJ.match(t) for t in xa + xb):
            na, nb = esp_normalised(xa), esp_normalised(xb)       # stores moved across a push / pop
            if collections.Counter(na) == collections.Counter(nb):
                return "order", "same instructions, other order across a push / pop (esp offsets taken at the hunk's start)"
            slots = sorted({mm[2] for t in na + nb for mm in SLOT_RE.finditer(t) if mm[1] == "esp"})
            if len(slots) <= 5:
                for perm in itertools.permutations(slots):
                    sm = {k: v for k, v in zip(slots, perm) if k != v}
                    if sm and collections.Counter(rename_slots(na, sm)) == collections.Counter(nb):
                        return "slots", ("other order across a push / pop (esp offsets taken at the hunk's start), "
                                         + " ".join(f"[{k or '+0'}]->[{v or '+0'}]" for k, v in sm.items()))
        s = sib_explain(xa, xb)
        if s:
            return "sib", s
        if all(t.startswith("f") for t in set(xa) ^ set(xb)):
            norm = lambda ls: sorted(re.sub(r"st\(\d\)", "st(N)", t) for t in ls)  # noqa: E731
            if norm(xa) == norm(xb):
                return "fpu", "same FPU instructions, other stack order"
            return "fpu", "FPU instructions differ"
        return None

    def frame_delta(self, a, b):
        fa, fb = frame_size(a), frame_size(b)
        return (fa, fb) if fa is not None and fb is not None and fa != fb else None

    def stack_mask(self, lines, frame):
        """Every `[esp ...]` / `[ebp ...]` operand reads `[esp S]` / `[ebp S]`, `sub|add esp, N` of a frame
        size reads `sub|add esp, F`."""
        sizes = set(frame)
        out = []
        for t in lines:
            m = ESP_ADJ.match(t)
            if m and int(m[2], 0) in sizes:
                out.append(f"{m[1]} esp, F")
            else:
                out.append(SLOT_RE.sub(lambda mm: f"[{mm[1]} S]", t))
        return out

    def frame_explain(self, xa, xb, frame):
        if len(xa) != len(xb) or self.stack_mask(xa, frame) != self.stack_mask(xb, frame):
            return None
        d = frame[0] - frame[1]
        for x, y in zip(xa, xb):
            if x == y:
                continue
            ma, mb = ESP_ADJ.match(x), ESP_ADJ.match(y)
            if ma and mb:
                if int(ma[2], 0) - int(mb[2], 0) != d:
                    return None
                continue
            oa = [slot_value(m) for m in SLOT_RE.finditer(x)]
            ob = [slot_value(m) for m in SLOT_RE.finditer(y)]
            if len(oa) != len(ob) or any(abs(p - q) not in (0, abs(d)) for p, q in zip(oa, ob)):
                return None
        sign = "-" if d < 0 else ""
        return f"stack offsets shifted by {sign}{abs(d):#x} (frame {frame[0]:#x} vs {frame[1]:#x})"

    def rename_registers(self, lines, mapping):
        return rename_regs(lines, {full_reg(k): full_reg(v) for k, v in mapping.items()})

    def one_renaming(self, a, b):
        if len(a) != len(b):
            return False
        fwd, back = {}, {}
        for x, y in zip(a, b):
            ta, tb = TOKEN_RE.findall(x), TOKEN_RE.findall(y)
            if len(ta) != len(tb) or TOKEN_RE.sub("T", x) != TOKEN_RE.sub("T", y):
                return False
            for p, q in zip(ta, tb):
                p = full_reg(p) if not p.startswith("[") else p
                q = full_reg(q) if not q.startswith("[") else q
                if fwd.setdefault(p, q) != q or back.setdefault(q, p) != p:
                    return False
        return True
