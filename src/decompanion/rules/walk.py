"""The code walk (rule S.codewalk): recursive descent over the code sections, and the Walker it uses.

Conventions it rests on (derived level; VC6 / LINK are the toolchain they were stated for):
  W1  a function's code is contiguous: every block of a function lies between its start and the next
      function's start, and its jump tables follow its code. A direct jump that crosses a known start is
      therefore a tail call to another function (VC6 emits `pop ..; jmp f` for `return f(args)`), and a
      jump-table entry never points past the next start.
  W2  a direct call target is a function start, unless it lies inside the calling function's own range
      (a local subroutine of assembly-written library code): then it is an inner label of that function.
  W3  a code address pushed or stored as an immediate at a relocation site, and a code address stored in a
      data section (a function pointer), is a function start.
  W4  a function ends at a return, at an unconditional jump (direct or indirect), and at alignment fill
      (Toolchain.fill_forms) reached by fall-through; a jump target is code whatever its first instruction.
      A call followed directly by a known start ends the function too: the callee does not return (VC6
      emits nothing after a call to a noreturn function such as _exit or _endthread). (Since milestone 3;
      before, the fall-through into the start was a C.walk conflict.)
The walk is repeated with the growing set of starts until that set is stable, so no walk ever runs into a
start found later. A walk that still runs into bytes another function owns is a conflict (C.walk): one of the
two starts is wrong.

The walk knows no instruction set: it reads the decoder of the target's ISA plugin (isa/base.py: Ins records
with a flow kind, direct targets, immediates, memory displacements, the table an indirect jump reads, fill
marks; TableShape for the extent of a jump table and its byte index table; field_starts for where a relocated
field may sit inside an instruction). x86-32 is isa/x86.py.

How it is computed (none of this changes a result):
- Every instruction is decoded once per rule run (the decoder memoises its records by address).
- A root's walk is a function of the bytes, the claims of other rules, and the starts between the root and
  the next start (W1 confines it there). Each iteration therefore replays a root's recorded walk instead of
  repeating it when the next start after the root is unchanged and the walk saw no byte another walk owns;
  everything else is walked again, in the same order as a walk from scratch.
"""
from __future__ import annotations

import bisect
from collections import defaultdict

from ..isa.base import CALL, CJUMP, IJUMP, JUMP, JUMPS, RET, Decoder
from ..ledger.fact import Kind, Level, Severity
from .engine import RuleContext, rule

D = Level.derived


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
        self.call_size = {}              # call site -> size of the call instruction
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
        for t, s, n in rec.calls:
            self.calls[t].add(s)
            self.call_size[s] = n
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
        field_starts = self.dec.field_starts
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
                    if ia != owner and ia in stops and recent and recent[-1].flow == CALL:   # W4: a call that does not return
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
                    if flow == CALL and ins.target is not None:          # W2
                        t = ins.target
                        if L <= t < hi:
                            rec.calls.append((t, ia, size))
                    elif flow not in JUMPS:                              # W3: a code immediate in a relocated field
                        for v in ins.imms:
                            if L <= v < hi and any(k in reloc_sites for k in field_starts(ins)):
                                rec.imms.append((v, ia))
                    if flow == RET:                                      # W4
                        break
                    if flow == JUMP or flow == CJUMP:
                        t = ins.target
                        if L <= t < hi:
                            if self.crosses_stop(ia, t) or t in stops and t != owner:   # W1: a tail call
                                rec.tails.append((t, ia))
                            else:
                                rec.jumps.append((t, ia))
                                work.append(t)
                        if flow == JUMP:                                 # W4
                            break
                        continue
                    if flow == IJUMP:                                    # W4
                        if ins.table is not None:
                            self.jump_table(ins, recent, owner, work, rec)
                        break
                break
        if self.rec is None:
            self.merge(rec)
        return self.extent[owner]

    def jump_table(self, jump, recent, owner, work, rec):
        """The table an indirect jump reads (W1: its entries are code of the owner, before the next start):
        entries are claimed while each holds an address in [owner, next start) and the bound the decoder found
        (TableShape.bound, unless an index table selects the entry) is not reached; an index table of `bound`
        entries is claimed when none of its bytes is owned yet."""
        tbl = jump.table
        if not self.in_code(tbl):
            return
        shape = self.dec.table_shape(jump, recent)
        bound, byte_tbl, w = shape.bound, shape.index_table, shape.entry_size
        limit = self.next_stop(owner)
        n = 0
        a = tbl
        while self.in_code(a) and a + w <= self.hi:
            if bound is not None and not byte_tbl and n >= bound:
                break
            v = self.dec.read_entry(a, w)
            if not (owner <= v < limit):
                break
            o = a - self.lo
            if self.kind[o] != 0:
                if self.owner[o] != owner:
                    rec.foreign = rec.foreign or self.kind[o] != 3
                else:
                    rec.probes.append(a)
                break
            self.claim(a, a + w, owner, 2)
            work.append(v)
            n += 1
            a += w
        if n:
            rec.tables.append((tbl, a, owner, "jumptable"))
        if byte_tbl is not None and bound is not None:
            end = byte_tbl + bound * shape.index_size
            free = True
            for p in range(byte_tbl, end):
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


@rule("S.codewalk", version="3", ceiling=D, outputs=("symbol", "start", "ref"),
      needs=("S.sections", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.thunk", "S.relocs"),
      helpers=(Record, Walker))
def codewalk(ctx: RuleContext):
    """Recursive descent over the code sections from every known start (exports, the entry point, the symbols
    of placed library sections, the entry the CRT calls), adding the starts the walk reveals (conventions
    W1..W4 in rules/walk.py: call targets, tail-call targets, code immediates at relocation sites, code
    pointers stored in data sections) and repeating until the set of starts is stable. A walked
    function owns [start, last byte it reached + 1) as a `func` symbol of derived extent (bytes inside it
    the walk did not reach are counted as holes); its jump tables and byte index tables are `jumptable` /
    `idxtable` symbols; calls (over the call instruction), tail calls, immediates and memory operands pointing
    into the image are `ref` facts. A walk that runs into bytes another function owns is a conflict (C.walk).
    Instructions come from the target's instruction-set plugin (isa/), fill forms from the toolchain."""
    img, tc = ctx.image, ctx.project.toolchain
    code_secs = [s for s in img.sections if s.holds_code]
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
    dec = ctx.project.isa.decoder(img, lo, hi, tc.fill_forms)
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
            yield ctx.fact(s, s + w.call_size[s], Kind.ref, {"rkind": "call", "to": t}, D)
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
