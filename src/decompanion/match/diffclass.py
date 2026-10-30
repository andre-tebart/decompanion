"""The instruction diff of one function and the classification of its hunks (lifted from the first attempt's
decomp/asmdiff.py and decomp/match/diffclass.py; the disassembly is the ISA plugin's listing, capstone for
x86, in-process).

What is compared (compare_function: the one reading of a function that grade, `dcp asmdiff` and `dcp
diffclass` share):
  ours        our compiled function's instructions (FunctionCode.code_data: up to the first compiler label
              after the code, where CL puts a switch's jump and index tables)
  original    the image's bytes from the address over the function's extent (the code walk's, else the source
              extent of L.src.extent), cut at its first switch table: a walk of the function's slot (from the
              address up to the next known start, rules/walk.py's Walker) finds the jump tables its indirect
              jumps read and their byte index tables. The source extent of a function the walk did not reach
              holds its tables (contiguity), the code walk's does not; either way the tables are no code.
  tables      when both sides have switch tables, they are compared as data (compare_tables): the bytes after
              our code against the original's from its first table on, every relocated entry of ours by the
              instruction it points to (the same instruction index, the same instruction of an aligned hunk,
              or a block of the same instructions up to its `ret` / `jmp`: a case block moved with the code
              around it is the same target), every other byte (the
              index tables, the fill between tables) by value. Equal tables are reported, never counted as a
              hunk; differing ones are a `table` difference that keeps the function from shape.
Both listings are placed at the original address (Isa.listing: numbers that are image addresses and our
relocated fields read X), the trailing alignment fill of each side is dropped, and difflib aligns the two
instruction lists. Each differing hunk (hunks within 4 equal instructions of each other are joined: a moved
instruction shows as a - and a + hunk) is explained by the first test that fits:
  fill    nothing but alignment fill forms on both sides
  order   the same instructions in another order (a multiset equality: no renaming needed)
  regs / slots / order (after a register renaming) / sib / fpu    the ISA's explanation (Isa.explain)
  frame   the frame-aligned diff only (below): the lines differ in their stack offsets alone, each by 0 or by
          the frame delta, the frame sizes by exactly the delta (Isa.frame_explain)
  code    anything else
The frame-aligned diff: when the two frames differ in size (Isa.frame_delta: `sub esp, 0xcc` against `sub
esp, 0xc8`), one slot more or less shifts every stack offset above it, so nearly every line that touches the
stack differs and the plain diff is one long `code` hunk. Then the lists are aligned a second time with every
stack offset and the frame size masked (Isa.stack_mask); the lines that are equal under the mask but differ
in their offsets form `frame` hunks of their own (never joined with the others), the rest is classified as
above. The frame-aligned verdict is taken when the plain one is no shape (a function the plain diff explains
keeps its verdict).
The branch targets: the listings read every address as X, a jump's target too, so a jump to another block of
the function would read the same as the original's. Every jump of ours with a target inside our code (Line.
target) is paired with the original's through the alignment (the equal runs; inside a hunk, the jumps of the
same text in order) and its target mapped the same way (the equal runs; the lines of an `order` hunk each to
the same instruction, the ones a renaming changed in order; the lines of any other hunk of equal length on
both sides one to one): the targets must be aligned instructions, or both the first line of the same `order`
hunk, or start the same code (same_code: walked side by side, unconditional jumps followed, the same
instructions up to aligned ones or the same `ret`: a jump to an identical copy of an epilogue, a block the
compiler placed elsewhere). Any other target is a
`branch` difference that keeps the function from shape; a jump whose target leaves the code on both sides
(the original's tail jump, our relocated one) is not compared.
The function-level verdict (grade B2, rules/grade.py): every hunk is explained, or the instructions left in
the code hunks are the same multiset on both sides (moved further than a hunk reaches), or the whole function
is equal under one bijective renaming of registers and stack slots (Isa.one_renaming); and the branch targets
agree; and the switch tables, when both sides have them, are equal.

The distance: the number of differing instructions on both sides (the - and + lines of the plain diff).
"""
from __future__ import annotations

import collections
import difflib
from dataclasses import dataclass, field

VERSION = "7"          # part of the classification cache key: bump when a class's criterion changes


def strip_fill(lines: list) -> list:
    """Drop the trailing alignment fill of a listing."""
    out = list(lines)
    while out and out[-1].fill:
        out.pop()
    return out


def ops(a: list[str], b: list[str]):
    return difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()


def distance(a: list[str], b: list[str]) -> int:
    """Differing instructions on both sides."""
    return sum(i2 - i1 + j2 - j1 for tag, i1, i2, j1, j2 in ops(a, b) if tag != "equal")


def join(raw) -> list[tuple[int, int, int, int]]:
    """Differing opcodes (i1, i2, j1, j2) joined into hunks when within 4 equal instructions of each other."""
    hs = []
    for i1, i2, j1, j2 in raw:
        if hs and i1 - hs[-1][1] <= 4 and j1 - hs[-1][3] <= 4:
            h = hs[-1]
            hs[-1] = (h[0], i2, h[2], j2)
        else:
            hs.append((i1, i2, j1, j2))
    return hs


def hunks(a: list[str], b: list[str]) -> list[tuple[int, int, int, int]]:
    return join((i1, i2, j1, j2) for tag, i1, i2, j1, j2 in ops(a, b) if tag != "equal")


def classify(A, B, isa, i1, i2, j1, j2):
    """(class, note) of one hunk of the listings A (ours) and B (the original's)."""
    a, b = [x.text for x in A[i1:i2]], [x.text for x in B[j1:j2]]
    if all(x.fill for x in A[i1:i2] + B[j1:j2]):
        return "fill", "alignment fill"
    if collections.Counter(a) == collections.Counter(b):
        return "order", "same instructions, other order"
    r = isa.explain(a, b, [x.text for x in A])
    return r if r else ("code", "")


def classify_hunks(A: list, B: list, isa) -> list[tuple[int, int, int, int, str, str]]:
    """(i1, i2, j1, j2, class, note) of every differing hunk of two listings (ours, the original's): the
    plain diff."""
    a, b = [x.text for x in A], [x.text for x in B]
    return [(i1, i2, j1, j2, *classify(A, B, isa, i1, i2, j1, j2)) for i1, i2, j1, j2 in hunks(a, b)]


def frame_hunks(A: list, B: list, isa, frame) -> list[tuple[int, int, int, int, str, str]]:
    """The hunks of the frame-aligned diff (module docstring): aligned with the stack offsets masked; the runs
    of lines equal under the mask but not in their text are hunks of their own, `frame` when Isa.frame_explain
    accepts them, else classified like any hunk."""
    a, b = [x.text for x in A], [x.text for x in B]
    ma, mb = isa.stack_mask(a, frame), isa.stack_mask(b, frame)
    other, shifted = [], []
    for tag, i1, i2, j1, j2 in ops(ma, mb):
        if tag != "equal":
            other.append((i1, i2, j1, j2))
            continue
        k = 0
        while k < i2 - i1:
            if a[i1 + k] == b[j1 + k]:
                k += 1
                continue
            e = k
            while e < i2 - i1 and a[i1 + e] != b[j1 + e]:
                e += 1
            shifted.append((i1 + k, i1 + e, j1 + k, j1 + e))
            k = e
    out = []
    for i1, i2, j1, j2 in shifted:
        note = isa.frame_explain(a[i1:i2], b[j1:j2], frame)
        out.append((i1, i2, j1, j2, "frame", note) if note else (i1, i2, j1, j2, *classify(A, B, isa, i1, i2, j1, j2)))
    out += [(i1, i2, j1, j2, *classify(A, B, isa, i1, i2, j1, j2)) for i1, i2, j1, j2 in join(other)]
    return sorted(out)


@dataclass
class Verdict:
    shape: bool                                     # B2 holds
    hunks: dict = field(default_factory=dict)       # class -> instructions in its hunks
    moved: bool = False
    renamed: bool = False
    code: list = field(default_factory=list)        # (instruction index, -lines, +lines) of the unexplained hunks
    distance: int = 0
    tables: dict | None = None                      # {entries, bytes, diffs} of the switch tables both sides have
    frame: list | None = None                       # [our frame size, the original's] of a frame-aligned verdict
    branches: list = field(default_factory=list)    # the jumps whose targets do not align (branch_diffs)

    def summary(self) -> str:
        hs = ", ".join(f"{k} {v}" for k, v in sorted(self.hunks.items(), key=lambda kv: -kv[1])) or "identical instructions"
        extra = "; the code hunks are moved instructions" if self.moved else (
            "; equal under one function-wide renaming" if self.renamed else "")
        if self.frame:
            extra += f"; frame {self.frame[0]:#x} vs {self.frame[1]:#x} (stack offsets aligned)"
        if self.branches:
            extra += f"; branch targets differ ({len(self.branches)}): " + "; ".join(self.branches[:3])
        t = self.tables
        if t is not None:
            if t["diffs"]:
                extra += f"; switch tables differ ({len(t['diffs'])}): " + "; ".join(t["diffs"][:3])
            else:
                extra += f"; switch tables equal ({t['entries']} entries, {t['bytes']} index bytes)"
        return hs + extra

    def to_json(self):
        return {"shape": self.shape, "hunks": self.hunks, "moved": self.moved, "renamed": self.renamed,
                "code": self.code, "distance": self.distance, "tables": self.tables, "frame": self.frame,
                "branches": self.branches}

    @classmethod
    def from_json(cls, d):
        return cls(d["shape"], d["hunks"], d["moved"], d["renamed"], [tuple(x) for x in d["code"]], d["distance"],
                   d.get("tables"), d.get("frame"), d.get("branches", []))


def aligned(A: list, B: list, hs) -> tuple[list, dict, set]:
    """(the pairs of jumps (our index, the original's), our instruction index -> the original's, the first
    lines (ours, the original's) of the `order` hunks) of two listings over their classified hunks (module
    docstring: the branch targets). The lines between the hunks are the equal runs; a run whose two sides
    differ in length (overlapping hunks of the frame-aligned diff) is not paired."""
    jumps, m, starts = [], {}, set()
    i = j = 0
    for i1, i2, j1, j2, cls, _ in sorted(hs) + [(len(A), len(A), len(B), len(B), "", "")]:
        if i1 - i == j1 - j > 0:
            m.update(zip(range(i, i1), range(j, j1)))
            jumps += [(k, j + k - i) for k in range(i, i1) if A[k].target is not None and B[j + k - i].target is not None]
        if cls == "order":                    # the same instructions: each to its own, the rest (renamed) in order
            same = collections.defaultdict(collections.deque)
            for k in range(j1, j2):
                same[B[k].text].append(k)
            rest = []
            for k in range(i1, i2):
                if same[A[k].text]:
                    m[k] = same[A[k].text].popleft()
                else:
                    rest.append(k)
            m.update(zip(rest, sorted(k for q in same.values() for k in q)))
            starts.add((i1, j1))
        elif i2 - i1 == j2 - j1 and cls != "fill":
            m.update(zip(range(i1, i2), range(j1, j2)))
        theirs = collections.defaultdict(collections.deque)
        for k in range(j1, j2):
            if B[k].target is not None:
                theirs[B[k].text].append(k)
        jumps += [(k, theirs[A[k].text].popleft()) for k in range(i1, i2)
                  if A[k].target is not None and theirs[A[k].text]]
        i, j = max(i, i2), max(j, j2)
    return jumps, m, starts


def same_code(A: list, B: list, ia: int, ib: int, m: dict, starts: set, depth: int = 4, steps: int = 24) -> bool:
    """The code from A[ia] and from B[ib] is the same (module docstring: the branch targets): walked side by
    side, every unconditional jump followed to its target (a block the compiler placed elsewhere, a fall-through
    against a jump), until both reach aligned instructions, or the same `ret` (an identical copy of an
    epilogue), or the same jump out of the code; the instructions on the way equal, and every conditional jump
    on the way going to the same code again (`depth` deep). At most `steps` instructions."""
    pos_a = {x.addr: i for i, x in enumerate(A)}
    pos_b = {x.addr: i for i, x in enumerate(B)}

    def follow(L, pos, i):
        for _ in range(8):
            if i is None or i >= len(L) or L[i].target is None or L[i].text.split(" ", 1)[0] != "jmp":
                break
            i = pos.get(L[i].target)
        return i if i is not None and i < len(L) else None
    for _ in range(steps):
        ia, ib = follow(A, pos_a, ia), follow(B, pos_b, ib)
        if ia is None or ib is None:
            return False
        if m.get(ia) == ib or (ia, ib) in starts:
            return True
        if A[ia].text != B[ib].text:
            return False
        mn = A[ia].text.split(" ", 1)[0]
        if mn in ("ret", "jmp"):              # the same return, or the same jump out of the code
            return True
        if A[ia].target is not None or B[ib].target is not None:
            ja, jb = pos_a.get(A[ia].target), pos_b.get(B[ib].target)
            if ja is None or jb is None or depth == 0 or not same_code(A, B, ja, jb, m, starts, depth - 1, steps):
                return False
        ia, ib = ia + 1, ib + 1
    return False


def branch_diffs(A: list, B: list, hs) -> list[str]:
    """The jumps of ours whose target does not align with the original's jump's (module docstring)."""
    if not A or not B:
        return []
    jumps, m, starts = aligned(A, B, hs)
    pos_a = {x.addr: i for i, x in enumerate(A)}
    pos_b = {x.addr: i for i, x in enumerate(B)}
    base = A[0].addr

    def where(t, pos):
        return f"+{t - base:#x}" if t in pos else "outside the code"
    out = []
    for i, j in jumps:
        ta, tb = A[i].target, B[j].target
        ia, ib = pos_a.get(ta), pos_b.get(tb)
        if ia is None and ib is None:
            continue
        if ia is not None and ib is not None and same_code(A, B, ia, ib, m, starts):
            continue
        out.append(f"{A[i].text.split(' ', 1)[0]} at +{A[i].addr - base:#x}: ours to {where(ta, pos_a)}, "
                   f"the original's to {where(tb, pos_b)}")
    return out


def judge(A: list, B: list, isa, hs, tables=None) -> Verdict:
    """The function-level verdict over classified hunks."""
    a, b = [x.text for x in A], [x.text for x in B]
    weight = collections.Counter()
    minus, plus, code = [], [], []
    for i1, i2, j1, j2, cls, info in hs:
        weight[cls] += i2 - i1 + j2 - j1
        if cls == "code":
            minus += a[i1:i2]
            plus += b[j1:j2]
            code.append((i1, a[i1:i2][:8], b[j1:j2][:8]))
    moved = bool(code) and collections.Counter(minus) == collections.Counter(plus)
    renamed = bool(code) and not moved and isa.one_renaming(a, b)
    bad = bool(tables and tables["diffs"])
    if bad:
        weight["table"] += len(tables["diffs"])
    branches = branch_diffs(A, B, hs)
    if branches:
        weight["branch"] += len(branches)
    return Verdict((not code or moved or renamed) and not bad and not branches, dict(weight), moved, renamed, code[:6],
                   distance(a, b), tables, branches=branches[:12])


def analyse(A: list, B: list, isa, tables=None) -> tuple[list, Verdict]:
    """(the hunks, the verdict) of two listings: the plain diff, or the frame-aligned one when the frames
    differ in size and the plain diff is no shape (module docstring)."""
    hs = classify_hunks(A, B, isa)
    v = judge(A, B, isa, hs, tables)
    if v.shape:
        return hs, v
    frame = isa.frame_delta([x.text for x in A], [x.text for x in B])
    if frame is None:
        return hs, v
    fh = frame_hunks(A, B, isa, frame)
    fv = judge(A, B, isa, fh, tables)
    fv.frame = list(frame)
    return fh, fv


def verdict(A: list, B: list, isa, tables=None) -> Verdict:
    return analyse(A, B, isa, tables)[1]


def code_size(isa, img, code: bytes, mask: bytes, addr: int, fill_forms) -> int:
    """Our function's code size: the end of its last instruction that is no alignment fill (CL pads a
    function's section with fill)."""
    lines = strip_fill(isa.listing(code, addr, mask, (img.base, img.end), fill_forms))
    return (lines[-1].addr + lines[-1].size - addr) if lines else len(code)


def listings(isa, img, code: bytes, mask: bytes, addr: int, orig_size: int, fill_forms):
    """(ours, the original's) listings at addr, trailing fill dropped; the original read up to its own code
    size (Original.code), so a shorter original does not bleed the next function or its tables into the diff."""
    rng = (img.base, img.end)
    A = strip_fill(isa.listing(code, addr, mask, rng, fill_forms))
    B = strip_fill(isa.listing(img.read(addr, orig_size), addr, None, rng, fill_forms))
    return A, B


# ------------------------------------------------------------------------------------------------ the original's tables
@dataclass
class Original:
    """The original function as the diff reads it: `code` its instruction bytes from the address (up to its
    first switch table inside the extent, trailing fill dropped; the extent itself when no table lies inside),
    `tables` the jump / index tables (lo, hi, kind) a walk of its slot finds."""
    code: int
    tables: list

    def to_json(self):
        return {"code": self.code, "tables": [list(t) for t in self.tables]}

    @classmethod
    def from_json(cls, d):
        return cls(d["code"], [tuple(t) for t in d["tables"]])


def original(isa, img, addr: int, extent: int, slot: int, fill_forms, align: int = 1) -> Original:
    """Walk the original's slot [addr, addr + slot) from addr (rules/walk.py's Walker: the jump tables its
    indirect jumps read, their byte index tables) and cut the extent [addr, addr + extent) at the first
    table inside it."""
    from ..rules.walk import Walker
    hi = addr + max(slot, extent)
    tables = []
    if hi > addr:
        w = Walker(isa.decoder(img, addr, hi, fill_forms), set(), set(), align)
        w.walk_root(addr)
        tables = sorted({(lo, h, k) for lo, h, _, k in w.tables})
    inside = [lo for lo, _, _ in tables if addr < lo < addr + extent]
    if not inside:
        return Original(extent, tables)
    end = min(inside)
    lines = strip_fill(isa.listing(img.read(addr, end - addr), addr, None, (img.base, img.end), fill_forms))
    return Original((lines[-1].addr + lines[-1].size - addr) if lines else end - addr, tables)


def index_map(A: list, B: list) -> tuple[dict, list]:
    """(our instruction index -> the original's, for the equal runs of the plain diff; the differing hunks)."""
    a, b = [x.text for x in A], [x.text for x in B]
    m = {}
    for tag, i1, i2, j1, j2 in ops(a, b):
        if tag == "equal":
            for k in range(i2 - i1):
                m[i1 + k] = j1 + k
    return m, hunks(a, b)


def block(L: list, i: int, limit: int = 12) -> list[str]:
    """The texts of the block that starts at instruction i: up to its first `ret` or `jmp` (included), at most
    `limit` instructions; a case block moved with its code reads the same on both sides."""
    out = []
    for x in L[i:i + limit]:
        out.append(x.text)
        if x.text.split(" ", 1)[0] in ("ret", "jmp"):
            break
    return out


def compare_tables(img, code, addr: int, A: list, B: list, tables: list, fill_forms) -> dict | None:
    """The switch tables of both sides as data (module docstring): {entries, bytes, diffs}; None when either
    side has none (our FunctionCode.code_len, the original's walked tables)."""
    from .compare import is_fill
    if code.code_len is None or not tables:
        return None
    t0, t1 = tables[0][0], max(h for _, h, _ in tables)
    if t0 < addr:
        return None
    ours, mask = code.data[code.code_len:], code.mask[code.code_len:]
    orig = img.read(t0, t1 - t0)
    sec = code.section
    relocs = {off - code.code_len: (r, s) for off, r, s in code.relocs if off >= code.code_len}
    pos_a = {x.addr - addr: i for i, x in enumerate(A)}
    pos_b = {x.addr - addr: i for i, x in enumerate(B)}
    m, hs = index_map(A, B)

    def same(ta, tb):
        if ta is not None and ta == tb:
            return True
        ia, ib = pos_a.get(ta), pos_b.get(tb)
        if ia is None or ib is None:
            return False
        return (m.get(ia) == ib or any(i1 <= ia < i2 and j1 <= ib < j2 for i1, i2, j1, j2 in hs)
                or block(A, ia) == block(B, ib))

    diffs, entries, nbytes = [], 0, 0
    n = min(len(ours), len(orig))
    k = 0
    while k < n:
        if mask[k]:
            r, s = relocs.get(k, (None, None))
            if r is None or r.width != 4 or k + 4 > n:
                diffs.append(f"+{k:#x}: a relocated field that is no table entry")
                k += max(1, r.width if r is not None else 1)
                continue
            entries += 1
            ta = (s.value + sec.addend(r) - code.start) if s is not None and s.section is sec else None
            tb = int.from_bytes(orig[k:k + 4], "little") - addr
            if not same(ta, tb):
                diffs.append(f"entry +{k:#x}: ours to +{ta:#x}, the original's to +{tb:#x}" if ta is not None
                             else f"entry +{k:#x}: ours points outside the function")
            k += 4
            continue
        nbytes += 1
        if ours[k] != orig[k]:
            diffs.append(f"byte +{k:#x}: {ours[k]:#04x} vs {orig[k]:#04x}")
        k += 1
    if len(ours) > n and not is_fill(ours[n:], fill_forms):
        diffs.append(f"ours has {len(ours) - n} table bytes more")
    if len(orig) > n:
        diffs.append(f"the original has {len(orig) - n} table bytes more")
    return {"entries": entries, "bytes": nbytes, "diffs": diffs[:12]}


def compare_function(isa, img, code, addr: int, extent: int, slot: int, fill_forms, align: int = 1, orig=None):
    """The one reading of a function that grade, `dcp asmdiff` and `dcp diffclass` share: (ours, the
    original's listings, Original, the tables compare) for our FunctionCode against the image at addr, the
    function's extent and slot (the bytes up to the next known start) in bytes."""
    o = orig if orig is not None else original(isa, img, addr, extent, slot, fill_forms, align)
    A, B = listings(isa, img, code.code_data, code.code_mask, addr, o.code, fill_forms)
    return A, B, o, compare_tables(img, code, addr, A, B, o.tables, fill_forms)
