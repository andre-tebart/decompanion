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
The walk is repeated with the growing set of starts until that set is stable, so no walk ever runs into a
start found later. A walk that still runs into bytes another function owns is a conflict (C.walk): one of the
two starts is wrong.

How it is computed (none of this changes a result):
- Every instruction is decoded once per rule run into a compact record (Ins). capstone's light decoder gives
  address, size, mnemonic and operand text; the full operand details are read only for an instruction whose
  text names a number inside the image (a memory operand or an immediate the walk records), a branch whose
  operand is not a plain number, and the first instruction of every mnemonic (its call / jump / ret group).
- A root's walk is a function of the bytes, the claims of other rules, and the starts between the root and
  the next start (W1 confines it there). Each iteration therefore replays a root's recorded walk instead of
  repeating it when the next start after the root is unchanged and the walk saw no byte another walk owns;
  everything else is walked again, in the same order as a walk from scratch.
"""
from __future__ import annotations

import bisect
import re
import struct
from collections import defaultdict

from ..disasm import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, decoder
from ..ledger.fact import Kind, Level, Severity
from .engine import RuleContext, rule

D = Level.derived
M32 = 0xffffffff
F_NONE, F_CALL, F_JUMP, F_RET = 0, 1, 2, 3
HEX = re.compile(r"0x([0-9a-f]+)")
NUMBER = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")


class Ins:
    """One decoded instruction, reduced to what the walk reads: flow (none / call / jump / ret), the immediate
    first operand of a call or jump (`target`), the memory operands whose displacement lies in the image
    (`mem`: (address, operand size)), every immediate operand (`imms`), the table of `jmp [index*4 + table]`
    (`jtab`), and whether the bytes are one alignment fill form."""
    __slots__ = ("addr", "size", "mn", "flow", "target", "mem", "imms", "jtab", "fill")

    def __init__(self, addr, size, mn, flow, target, mem, imms, jtab, fill):
        self.addr, self.size, self.mn, self.flow, self.target = addr, size, mn, flow, target
        self.mem, self.imms, self.jtab, self.fill = mem, imms, jtab, fill


class Decoder:
    """Decodes the code range of an image into Ins records, memoised by address for one rule run."""

    def __init__(self, img, code_lo, code_hi, fill_forms):
        self.img = img
        self.lo, self.hi = code_lo, code_hi
        self.code = img.read(code_lo, code_hi - code_lo)
        self.md = decoder()
        self.fill_forms = frozenset(fill_forms)
        self.cache: dict[int, Ins] = {}
        self.flows: dict[str, int] = {}          # mnemonic -> flow, from the first full decode of it
        self.ibase, self.iend = img.base, img.end

    def _in_image(self, v):
        return self.ibase <= v < self.iend

    def full(self, addr, size) -> Ins:
        """The record from capstone's operand details."""
        o = addr - self.lo
        ins = next(self.md.disasm(self.code[o:o + size], addr, 1))
        flow = F_CALL if ins.group(CS_GRP_CALL) else F_JUMP if ins.group(CS_GRP_JUMP) else F_RET if ins.group(CS_GRP_RET) else F_NONE
        self.flows.setdefault(ins.mnemonic, flow)
        ops = ins.operands
        target = ops[0].imm if flow in (F_CALL, F_JUMP) and ops and ops[0].type == X86_OP_IMM else None
        mem = tuple((op.mem.disp & M32, op.size) for op in ops
                    if op.type == X86_OP_MEM and op.mem.disp and self._in_image(op.mem.disp & M32))
        imms = tuple(op.imm for op in ops if op.type == X86_OP_IMM)
        jtab = None
        if ins.mnemonic == "jmp" and ops and ops[0].type == X86_OP_MEM and ops[0].mem.base == X86_REG_INVALID \
                and ops[0].mem.index != X86_REG_INVALID and ops[0].mem.scale == 4:
            jtab = ops[0].mem.disp & M32
        return Ins(addr, ins.size, ins.mnemonic, flow, target, mem, imms, jtab, bytes(ins.bytes) in self.fill_forms)

    def make(self, addr, size, mn, ops) -> Ins:
        flow = self.flows.get(mn)
        if flow is None:
            return self.full(addr, size)
        if flow in (F_CALL, F_JUMP):
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
        return Ins(addr, size, mn, flow, target, (), (), None, self.code[o:o + size] in self.fill_forms)

    def detail(self, addr):
        """capstone's full instruction at addr (for the few reads the records do not keep)."""
        o = addr - self.lo
        return next(self.md.disasm(self.code[o:o + 16], addr, 1))

    def decode(self, addr):
        """Instructions from addr on, in address order, until the bytes stop decoding or the code ends."""
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


class Record:
    """What one root's walk did: its claims in order, its references, the positions where it stopped for a
    reason other than a foreign byte (probes), whether it saw a byte another walk owns (foreign), the next
    start after the root when it walked (ns), its extent."""
    __slots__ = ("claims", "calls", "jumps", "tails", "imms", "operands", "tables", "overlaps", "probes", "foreign", "ns", "extent")

    def __init__(self, ns=0):
        self.claims, self.calls, self.jumps, self.tails, self.imms = [], [], [], [], []
        self.operands, self.tables, self.overlaps, self.probes = [], [], [], []
        self.foreign, self.ns, self.extent = False, ns, 0


class Walker:
    def __init__(self, dec: Decoder, reloc_sites, stops):
        self.dec = dec
        self.img = dec.img
        self.lo, self.hi = dec.lo, dec.hi
        self.code = dec.code
        n = self.hi - self.lo
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
        self.claimed = defaultdict(list)  # owner -> [(lo, hi, kind)] (every byte is claimed at most once)
        self.reloc_sites = reloc_sites
        self.stops = set(stops)
        self.sorted_stops = sorted(self.stops)
        self.rec: Record | None = None

    def in_code(self, a):
        return self.lo <= a < self.hi

    def crosses_stop(self, a, b):
        """Is there a stop s with min(a, b) < s <= max(a, b)? (a jump from a to b leaves the function)"""
        lo, hi = (a, b) if a < b else (b, a)
        i = bisect.bisect_right(self.sorted_stops, lo)
        return i < len(self.sorted_stops) and self.sorted_stops[i] <= hi

    def next_stop(self, a):
        i = bisect.bisect_right(self.sorted_stops, a)
        return self.sorted_stops[i] if i < len(self.sorted_stops) else self.hi

    def claim(self, lo, hi, owner, kind):
        a, b = lo - self.lo, hi - self.lo
        self.owner[a:b] = [owner] * (b - a)
        self.kind[a:b] = bytes((kind,)) * (b - a)
        if kind != 3:
            self.claimed[owner].append((lo, hi, kind))
            if self.rec is not None:
                self.rec.claims.append((lo, hi, kind))
        if kind == 1:   # a function's extent is its code; its tables are symbols of their own after it
            self.extent[owner] = max(self.extent.get(owner, owner), hi)

    # ------------------------------------------------------------------ records
    def merge(self, rec: Record):
        """Add a record's references to the walk's (claims are applied separately)."""
        for t, s in rec.calls:
            self.calls[t].add(s)
        for t, s in rec.jumps:
            self.jumps[t].add(s)
        for t, s in rec.tails:
            self.tails[t].add(s)
        for t, s in rec.imms:
            self.imms[t].add(s)
        self.operands.extend(rec.operands)
        self.tables.extend(rec.tables)
        self.overlaps.extend(rec.overlaps)

    def replay(self, root, rec: Record) -> bool:
        """Apply a recorded walk of root when it is what walking again would do now: the next start after the
        root is the same, the walk saw no byte another walk owned, and none of its claimed or probed bytes is
        owned by another walk now. False (and nothing applied) otherwise."""
        if rec.foreign or rec.ns != self.next_stop(root):
            return False
        kind, owner, L = self.kind, self.owner, self.lo
        for lo, hi, _ in rec.claims:
            if any(kind[lo - L:hi - L]):
                return False
        for lo, hi, k in rec.claims:
            self.owner[lo - L:hi - L] = [root] * (hi - lo)
            self.kind[lo - L:hi - L] = bytes((k,)) * (hi - lo)
        for p in rec.probes:
            o = p - L
            if kind[o] and owner[o] != root:
                for lo, hi, _ in rec.claims:
                    self.owner[lo - L:hi - L] = [0] * (hi - lo)
                    self.kind[lo - L:hi - L] = bytes(hi - lo)
                return False
        self.claimed[root].extend(rec.claims)
        self.extent[root] = rec.extent
        self.merge(rec)
        return True

    def walk_root(self, root) -> Record:
        """Walk a root from scratch, recording what it did, and add its references."""
        rec = self.rec = Record(self.next_stop(root))
        try:
            self.walk(root)
        finally:
            self.rec = None
        rec.extent = self.extent[root]
        self.merge(rec)
        return rec

    # ------------------------------------------------------------------ walking
    def walk(self, start, owner=None):
        """Walk from start on behalf of owner (the function start; start itself for a root, an inner label
        otherwise). Returns the owner's extent end."""
        owner = start if owner is None else owner
        self.extent.setdefault(owner, owner)
        rec = self.rec if self.rec is not None else Record()
        kind, own, L, hi = self.kind, self.owner, self.lo, self.hi
        stops, reloc_sites = self.stops, self.reloc_sites
        work = [start]
        while work:
            a = work.pop()
            target = a
            recent = []
            while L <= a < hi:
                o = a - L
                if kind[o] == 1 and own[o] == owner:
                    rec.probes.append(a)
                    break
                if kind[o] != 0 and own[o] != owner:
                    rec.overlaps.append((owner, a, own[o]))
                    rec.foreign = rec.foreign or kind[o] != 3
                    break
                if a != owner and a in stops:
                    rec.probes.append(a)
                    break
                for ins in self.dec.decode(a):
                    ia = ins.addr
                    io = ia - L
                    if kind[io] == 1 and own[io] == owner:
                        rec.probes.append(ia)
                        break
                    if kind[io] != 0 and own[io] != owner:
                        rec.overlaps.append((owner, ia, own[io]))
                        rec.foreign = rec.foreign or kind[io] != 3
                        break
                    if ia != owner and ia in stops:
                        rec.probes.append(ia)
                        break
                    if ins.fill and ia != target:
                        rec.probes.append(ia)
                        break
                    size = ins.size
                    self.claim(ia, ia + size, owner, 1)
                    recent.append(ins)
                    if len(recent) > 12:
                        del recent[0]
                    for disp, osize in ins.mem:
                        rec.operands.append((ia, size, disp, osize))
                    flow = ins.flow
                    if flow == F_CALL and ins.target is not None:
                        t = ins.target
                        if L <= t < hi:
                            rec.calls.append((t, ia))
                    elif flow != F_JUMP:
                        for v in ins.imms:
                            if L <= v < hi and any((ia + k) in reloc_sites for k in range(1, size - 3)):
                                rec.imms.append((v, ia))
                    if flow == F_RET:
                        break
                    if flow == F_JUMP:
                        if ins.target is not None:
                            t = ins.target
                            if L <= t < hi:
                                if self.crosses_stop(ia, t) or t in stops and t != owner:
                                    rec.tails.append((t, ia))
                                else:
                                    rec.jumps.append((t, ia))
                                    work.append(t)
                            if ins.mn == "jmp":
                                break
                            continue
                        if ins.jtab is not None:
                            self.jump_table(ins.jtab, recent, owner, work, rec)
                        break
                break
        if self.rec is None:
            self.merge(rec)
        return self.extent[owner]

    def jump_table(self, tbl, recent, owner, work, rec):
        if not self.in_code(tbl):
            return
        bound = None
        byte_tbl = None
        for r in reversed(recent[:-1]):
            if r.mn not in ("cmp", "movzx", "mov"):
                continue
            ins = self.dec.detail(r.addr)
            if ins.mnemonic == "cmp" and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM \
                    and ins.operands[0].type == X86_OP_REG and bound is None and 0 <= ins.operands[1].imm < 0x400:
                bound = ins.operands[1].imm + 1
            if ins.mnemonic in ("movzx", "mov") and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM \
                    and ins.operands[1].size == 1 and (ins.operands[1].mem.index != X86_REG_INVALID or ins.operands[1].mem.base != X86_REG_INVALID) \
                    and self.in_code(ins.operands[1].mem.disp & M32) and byte_tbl is None:
                byte_tbl = ins.operands[1].mem.disp & M32
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
                if self.owner[o] != owner:
                    rec.foreign = rec.foreign or self.kind[o] != 3
                else:
                    rec.probes.append(a)
                break
            self.claim(a, a + 4, owner, 2)
            work.append(v)
            n += 1
            a += 4
        if n:
            rec.tables.append((tbl, a, owner, "jumptable"))
        if byte_tbl is not None and bound is not None:
            end = byte_tbl + bound
            free = True
            for i in range(bound):
                p = byte_tbl + i
                if not self.in_code(p):
                    continue
                o = p - self.lo
                if self.kind[o] != 0:
                    free = False
                    if self.owner[o] != owner:
                        rec.foreign = rec.foreign or self.kind[o] != 3
                else:
                    rec.probes.append(p)
            if free:
                self.claim(byte_tbl, min(end, self.hi), owner, 2)
                rec.tables.append((byte_tbl, min(end, self.hi), owner, "idxtable"))

    def counts(self, owner, lo, hi):
        """(code bytes, table bytes) the owner claimed inside [lo, hi)."""
        code = table = 0
        for a, b, k in self.claimed.get(owner, ()):
            n = min(b, hi) - max(a, lo)
            if n > 0:
                if k == 1:
                    code += n
                else:
                    table += n
        return code, table


@rule("S.codewalk", version="2", ceiling=D, outputs=("symbol", "start", "ref"),
      needs=("S.sections", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.thunk", "S.relocs"),
      helpers=(Ins, Decoder, Record, Walker))
def codewalk(ctx: RuleContext):
    """Recursive descent over the code sections from every known start (exports, the entry point, the symbols
    of placed library sections, the entry the CRT calls), adding the starts the walk reveals (conventions
    W1..W4 in rules/walk.py: call targets, tail-call targets, code immediates at relocation sites, code
    pointers stored in data sections) and repeating until the set of starts is stable. A walked
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
    claimed = sorted((f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.value.get("skind") in ("func", "thunk") and lo <= f.lo < hi)
    claimed_starts = {a for a, _ in claimed}
    claimed_los = [a for a, _ in claimed]

    def inside_claimed(t):
        i = bisect.bisect_right(claimed_los, t) - 1
        while i >= 0:
            a, b = claimed[i]
            if a <= t < b:
                return True
            i -= 1
            if i >= 0 and claimed[i][0] < t - 0x100000:
                break
        return False

    known: dict[int, str] = {}
    for f in ctx.facts(Kind.start):
        if lo <= f.lo < hi and not inside_claimed(f.lo):
            known.setdefault(f.lo, f.value["how"])
    derived: dict[int, str] = {}
    w = None
    inner: dict[int, int] = {}
    dec = Decoder(img, lo, hi, tc.fill_forms)
    records: dict[int, Record] = {}
    for _ in range(25):
        roots = dict(known)
        roots.update({k: v for k, v in derived.items() if k not in roots})
        w = Walker(dec, reloc_sites, set(roots) | claimed_starts)
        for a, b in claimed:
            w.claim(a, b, a, 3)
            w.extent.pop(a, None)
        for r in sorted(roots):
            rec = records.get(r)
            if rec is None or not w.replay(r, rec):
                records[r] = w.walk_root(r)
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
        n_walked, n_table = w.counts(r, r, e)
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
