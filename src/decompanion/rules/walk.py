"""The code walk (rule S.codewalk): recursive descent over the code sections, and the Walker it uses.

Conventions it rests on (VC6 / LINK, derived level):
  W1  a function's code is contiguous: every block of a function lies between its start and the next
      function's start, and its jump tables follow its code. A direct jump that crosses a known start is
      therefore a tail call to another function (VC6 emits `pop ..; jmp f` for `return f(args)`), and a
      jump-table entry never points past the next start.
  W2  a direct `call` target is a function start, unless it lies inside the calling function's own range
      (a local subroutine of assembly-written library code): then it is an inner label of that function.
  W3  a code address pushed or stored as an immediate at a relocation site, and a code address stored in a
      data section (a function pointer), is a function start.
  W4  a function ends at `ret`, at an unconditional `jmp`, and at alignment fill reached by fall-through; a
      jump target is code whatever its first instruction.
The walk is repeated from scratch with the growing set of starts until that set is stable, so no walk ever
runs into a start found later. A walk that still runs into bytes another function owns is a conflict (C.walk):
one of the two starts is wrong.
"""
from __future__ import annotations

import bisect
import struct
from collections import defaultdict

from ..disasm import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, decoder
from ..ledger.fact import Kind, Level, Severity
from .engine import RuleContext, rule

D = Level.derived


class Walker:
    def __init__(self, img, code_lo, code_hi, fill_forms, reloc_sites, stops, cache=None):
        self.img = img
        self.cache = {} if cache is None else cache   # address -> decoded instruction, shared across walks
        self.lo, self.hi = code_lo, code_hi
        self.code = img.read(code_lo, code_hi - code_lo)
        self.md = decoder()
        n = code_hi - code_lo
        self.owner = [0] * n
        self.kind = bytearray(n)         # 1 code, 2 table data, 3 placed by another rule
        self.calls = defaultdict(set)    # target -> call sites
        self.jumps = defaultdict(set)    # direct jump target -> sites (within the function)
        self.tails = defaultdict(set)    # tail-call target -> sites
        self.imms = defaultdict(set)     # code immediate -> sites
        self.operands = []               # (site, size, target, operand size)
        self.tables = []                 # (lo, hi, owner, skind)
        self.overlaps = []               # (owner, addr, other owner)
        self.extent = {}                 # owner -> highest claimed address + 1
        self.fill_forms = fill_forms
        self.reloc_sites = reloc_sites
        self.stops = set(stops)
        self.sorted_stops = sorted(self.stops)

    def in_code(self, a):
        return self.lo <= a < self.hi

    def is_fill(self, ins):
        return bytes(ins.bytes) in self.fill_forms

    def crosses_stop(self, a, b):
        """Is there a stop s with min(a, b) < s <= max(a, b)? (a jump from a to b leaves the function)"""
        lo, hi = (a, b) if a < b else (b, a)
        i = bisect.bisect_right(self.sorted_stops, lo)
        return i < len(self.sorted_stops) and self.sorted_stops[i] <= hi

    def next_stop(self, a):
        i = bisect.bisect_right(self.sorted_stops, a)
        return self.sorted_stops[i] if i < len(self.sorted_stops) else self.hi

    def claim(self, lo, hi, owner, kind):
        for o in range(lo - self.lo, hi - self.lo):
            self.owner[o] = owner
            self.kind[o] = kind
        if kind == 1:   # a function's extent is its code; its tables are symbols of their own after it
            self.extent[owner] = max(self.extent.get(owner, owner), hi)

    def decode(self, addr):
        cache = self.cache
        while self.in_code(addr):
            ins = cache.get(addr)
            if ins is not None:
                yield ins
                addr = ins.address + ins.size
                continue
            o = addr - self.lo
            got = False
            for ins in self.md.disasm(self.code[o:o + 0x400], addr):
                got = True
                cache[ins.address] = ins
                yield ins
                addr = ins.address + ins.size
            if not got:
                return
            if addr < self.lo + o + 0x400 - 16:
                return

    def walk(self, start, owner=None):
        """Walk from start on behalf of owner (the function start; start itself for a root, an inner label
        otherwise). Returns the owner's extent end."""
        owner = start if owner is None else owner
        self.extent.setdefault(owner, owner)
        work = [start]
        while work:
            a = work.pop()
            target = a
            recent = []
            while self.in_code(a):
                o = a - self.lo
                if self.kind[o] == 1 and self.owner[o] == owner:
                    break
                if self.kind[o] != 0 and self.owner[o] != owner:
                    self.overlaps.append((owner, a, self.owner[o]))
                    break
                if a != owner and a in self.stops:
                    break
                stop = True
                for ins in self.decode(a):
                    ia = ins.address
                    io = ia - self.lo
                    if self.kind[io] == 1 and self.owner[io] == owner:
                        break
                    if self.kind[io] != 0 and self.owner[io] != owner:
                        self.overlaps.append((owner, ia, self.owner[io]))
                        break
                    if ia != owner and ia in self.stops:
                        break
                    if self.is_fill(ins) and ia != target:
                        break
                    self.claim(ia, ia + ins.size, owner, 1)
                    recent.append(ins)
                    recent = recent[-12:]
                    mn = ins.mnemonic
                    for op in ins.operands:
                        if op.type == X86_OP_MEM and op.mem.disp and self.img.in_image(op.mem.disp & 0xffffffff):
                            self.operands.append((ia, ins.size, op.mem.disp & 0xffffffff, op.size))
                    if ins.group(CS_GRP_CALL) and ins.operands and ins.operands[0].type == X86_OP_IMM:
                        t = ins.operands[0].imm
                        if self.in_code(t):
                            self.calls[t].add(ia)
                    elif not ins.group(CS_GRP_JUMP):
                        for op in ins.operands:
                            if op.type == X86_OP_IMM and self.in_code(op.imm) and \
                                    any((ia + k) in self.reloc_sites for k in range(1, ins.size - 3)):
                                self.imms[op.imm].add(ia)
                    if ins.group(CS_GRP_RET):
                        break
                    if ins.group(CS_GRP_JUMP):
                        op = ins.operands[0] if ins.operands else None
                        if op is not None and op.type == X86_OP_IMM:
                            t = op.imm
                            if self.in_code(t):
                                if self.crosses_stop(ia, t) or t in self.stops and t != owner:
                                    self.tails[t].add(ia)
                                else:
                                    self.jumps[t].add(ia)
                                    work.append(t)
                            if mn == "jmp":
                                break
                            continue
                        if mn == "jmp" and op is not None and op.type == X86_OP_MEM and op.mem.base == X86_REG_INVALID \
                                and op.mem.index != X86_REG_INVALID and op.mem.scale == 4:
                            self.jump_table(op.mem.disp & 0xffffffff, recent, owner, work)
                        break
                break
        return self.extent[owner]

    def jump_table(self, tbl, recent, owner, work):
        if not self.in_code(tbl):
            return
        bound = None
        byte_tbl = None
        for ins in reversed(recent[:-1]):
            if ins.mnemonic == "cmp" and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM \
                    and ins.operands[0].type == X86_OP_REG and bound is None and 0 <= ins.operands[1].imm < 0x400:
                bound = ins.operands[1].imm + 1
            if ins.mnemonic in ("movzx", "mov") and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM \
                    and ins.operands[1].size == 1 and (ins.operands[1].mem.index != X86_REG_INVALID or ins.operands[1].mem.base != X86_REG_INVALID) \
                    and self.in_code(ins.operands[1].mem.disp & 0xffffffff) and byte_tbl is None:
                byte_tbl = ins.operands[1].mem.disp & 0xffffffff
        limit = self.next_stop(owner)
        n = 0
        a = tbl
        while self.in_code(a) and a + 4 <= self.hi:
            if bound is not None and not byte_tbl and n >= bound:
                break
            v = struct.unpack_from("<I", self.code, a - self.lo)[0]
            if not (owner <= v < limit):
                break
            o = a - self.lo
            if self.kind[o] != 0:
                break
            self.claim(a, a + 4, owner, 2)
            work.append(v)
            n += 1
            a += 4
        if n:
            self.tables.append((tbl, a, owner, "jumptable"))
        if byte_tbl is not None and bound is not None:
            end = byte_tbl + bound
            if all(self.kind[byte_tbl + i - self.lo] == 0 for i in range(bound) if self.in_code(byte_tbl + i)):
                self.claim(byte_tbl, min(end, self.hi), owner, 2)
                self.tables.append((byte_tbl, min(end, self.hi), owner, "idxtable"))


@rule("S.codewalk", version="2", ceiling=D, outputs=("symbol", "start", "ref"),
      needs=("S.sections", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.thunk", "S.relocs"))
def codewalk(ctx: RuleContext):
    """Recursive descent over the code sections from every known start (exports, the entry point, the symbols
    of placed library sections, the entry the CRT calls), adding the starts the walk reveals (conventions
    W1..W4 in rules/walk.py: call targets, tail-call targets, code immediates at relocation sites, code
    pointers stored in data sections) and repeating from scratch until the set of starts is stable. A walked
    function owns [start, last byte it reached + 1) as a `func` symbol of derived extent (bytes inside it
    the walk did not reach are counted as holes); its jump tables and byte index tables are `jumptable` /
    `idxtable` symbols; calls, jumps, tail calls, immediates and memory operands pointing into the image are
    `ref` facts. A walk that runs into bytes another function owns is a conflict (C.walk)."""
    img, tc = ctx.image, ctx.project.toolchain
    code_secs = [s for s in img.sections if s.code or s.executable]
    if not code_secs:
        return
    lo = min(s.va for s in code_secs)
    hi = max(s.end for s in code_secs)
    reloc_sites = {f.lo for f in ctx.facts(Kind.ref) if f.value["rkind"] == "reloc"}
    data_ptrs = {f.value["to"] for f in ctx.facts(Kind.ref)
                 if f.value["rkind"] == "reloc" and not any(s.va <= f.lo < s.end for s in code_secs)}
    claimed = [(f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.value.get("skind") in ("func", "thunk") and lo <= f.lo < hi]
    claimed_starts = {a for a, _ in claimed}

    def inside_claimed(t):
        return any(a <= t < b for a, b in claimed)

    known: dict[int, str] = {}
    for f in ctx.facts(Kind.start):
        if lo <= f.lo < hi and not inside_claimed(f.lo):
            known.setdefault(f.lo, f.value["how"])
    derived: dict[int, str] = {}
    w = None
    inner: dict[int, int] = {}
    cache: dict = {}
    for _ in range(25):
        roots = dict(known)
        roots.update({k: v for k, v in derived.items() if k not in roots})
        w = Walker(img, lo, hi, set(tc.fill_forms), reloc_sites, set(roots) | claimed_starts, cache)
        for a, b in claimed:
            w.claim(a, b, a, 3)
            w.extent.pop(a, None)
        for r in sorted(roots):
            w.walk(r)
        # W2: a call target called only from inside the one function whose range holds it is an inner label of
        # that function (walked on its behalf when the function's own walk did not reach it)
        inner = {}
        changed = True
        while changed:
            changed = False
            for t, sites in sorted(w.calls.items()):
                if t in roots or t in inner:
                    continue
                owners = {w.owner[s - lo] for s in sites if w.kind[s - lo] == 1}
                if len(owners) != 1:
                    continue
                o = owners.pop()
                if o in w.extent and o < t < w.extent[o]:
                    inner[t] = o
                    if w.kind[t - lo] == 0:
                        w.walk(t, o)
                    changed = True
        new: dict[int, str] = {}
        for t, how in [(t, "call") for t in w.calls] + [(t, "tail") for t in w.tails] + [(t, "immediate") for t in w.imms]:
            if t in roots or t in inner or inside_claimed(t) or not (lo <= t < hi):
                continue
            new.setdefault(t, how)
        if not new:
            for t in sorted(data_ptrs):
                if lo <= t < hi and t not in roots and t not in inner and not inside_claimed(t) and w.kind[t - lo] == 0:
                    new[t] = "fptr"
        if not new and set(derived) <= set(roots):
            break
        derived.update(new)
    roots = dict(known)
    roots.update({k: v for k, v in derived.items() if k not in roots})
    for r in sorted(roots):
        e = w.extent.get(r, r)
        if e <= r:
            continue
        n_walked = sum(1 for o in range(r - lo, e - lo) if w.owner[o] == r and w.kind[o] == 1)
        n_table = sum(1 for o in range(r - lo, e - lo) if w.owner[o] == r and w.kind[o] == 2)
        holes = (e - r) - n_walked - n_table
        yield ctx.fact(r, r + 1, Kind.start, {"skind": "func", "how": roots[r]}, D)
        v = {"skind": "func", "extent": "derived", "walked": n_walked, "holes": holes}
        labels = sorted(t for t, o in inner.items() if o == r)
        if labels:
            v["inner"] = labels
        yield ctx.fact(r, e, Kind.symbol, v, D)
    for tlo, thi, owner, sk in w.tables:
        if thi > tlo:
            yield ctx.fact(tlo, thi, Kind.symbol, {"skind": sk, "extent": "derived", "fn": owner}, D)
    for t, sites in w.calls.items():
        for s in sorted(sites):
            yield ctx.fact(s, s + 5, Kind.ref, {"rkind": "call", "to": t}, D)
    for t, sites in w.tails.items():
        for s in sorted(sites):
            yield ctx.fact(s, s + 1, Kind.ref, {"rkind": "tail", "to": t}, D)
    for t, sites in w.imms.items():
        for s in sorted(sites):
            yield ctx.fact(s, s + 1, Kind.ref, {"rkind": "immediate", "to": t}, D)
    seen = set()
    for site, size, target, osize in w.operands:
        if (site, target) in seen:
            continue
        seen.add((site, target))
        yield ctx.fact(site, site + size, Kind.ref, {"rkind": "operand", "to": target, "size": osize}, D)
    for owner, addr, other in sorted(set(w.overlaps)):
        yield ctx.conflict(Severity.error, "C.walk", addr, addr + 1,
                           f"the walk from {owner:#x} ({roots.get(owner, 'inner')}) runs into bytes owned by {other:#x}: one start is wrong",
                           a=f"start:{owner:#x}", b=f"start:{other:#x}")
