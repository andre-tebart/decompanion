"""The instruction diff of one function and the classification of its hunks (lifted from the first attempt's
decomp/asmdiff.py and decomp/match/diffclass.py; the disassembly is the ISA plugin's listing, capstone for
x86, in-process).

Both sides are listed at the original address (Isa.listing: numbers that are image addresses and our
relocated fields read X), the trailing alignment fill of each side is dropped, and difflib aligns the two
instruction lists. Each differing hunk (hunks within 4 equal instructions of each other are joined: a moved
instruction shows as a - and a + hunk) is explained by the first test that fits:
  fill    nothing but alignment fill forms on both sides
  order   the same instructions in another order (a multiset equality: no renaming needed)
  regs / slots / order (after a register renaming) / sib / fpu    the ISA's explanation (Isa.explain)
  code    anything else
The function-level verdict (grade B2, rules/grade.py): every hunk is explained, or the instructions left in
the code hunks are the same multiset on both sides (moved further than a hunk reaches), or the whole function
is equal under one bijective renaming of registers and stack slots (Isa.one_renaming).

The distance: the number of differing instructions on both sides (the - and + lines of the diff).
"""
from __future__ import annotations

import collections
import difflib
from dataclasses import dataclass, field

VERSION = "1"          # part of the classification cache key: bump when a class's criterion changes


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


def hunks(a: list[str], b: list[str]) -> list[tuple[int, int, int, int]]:
    hs = []
    for tag, i1, i2, j1, j2 in ops(a, b):
        if tag == "equal":
            continue
        if hs and i1 - hs[-1][1] <= 4 and j1 - hs[-1][3] <= 4:
            h = hs[-1]
            hs[-1] = (h[0], i2, h[2], j2)
        else:
            hs.append((i1, i2, j1, j2))
    return hs


def classify_hunks(A: list, B: list, isa) -> list[tuple[int, int, int, int, str, str]]:
    """(i1, i2, j1, j2, class, note) of every differing hunk of two listings (ours, the original's)."""
    a, b = [x.text for x in A], [x.text for x in B]
    out = []
    for i1, i2, j1, j2 in hunks(a, b):
        if all(x.fill for x in A[i1:i2] + B[j1:j2]):
            cls, info = "fill", "alignment fill"
        elif collections.Counter(a[i1:i2]) == collections.Counter(b[j1:j2]):
            cls, info = "order", "same instructions, other order"
        else:
            r = isa.explain(a[i1:i2], b[j1:j2], a)
            cls, info = r if r else ("code", "")
        out.append((i1, i2, j1, j2, cls, info))
    return out


@dataclass
class Verdict:
    shape: bool                                     # B2 holds
    hunks: dict = field(default_factory=dict)       # class -> instructions in its hunks
    moved: bool = False
    renamed: bool = False
    code: list = field(default_factory=list)        # (instruction index, -lines, +lines) of the unexplained hunks
    distance: int = 0

    def summary(self) -> str:
        hs = ", ".join(f"{k} {v}" for k, v in sorted(self.hunks.items(), key=lambda kv: -kv[1])) or "identical instructions"
        extra = "; the code hunks are moved instructions" if self.moved else (
            "; equal under one function-wide renaming" if self.renamed else "")
        return hs + extra

    def to_json(self):
        return {"shape": self.shape, "hunks": self.hunks, "moved": self.moved, "renamed": self.renamed,
                "code": self.code, "distance": self.distance}

    @classmethod
    def from_json(cls, d):
        return cls(d["shape"], d["hunks"], d["moved"], d["renamed"], [tuple(x) for x in d["code"]], d["distance"])


def verdict(A: list, B: list, isa) -> Verdict:
    a, b = [x.text for x in A], [x.text for x in B]
    weight = collections.Counter()
    minus, plus, code = [], [], []
    for i1, i2, j1, j2, cls, info in classify_hunks(A, B, isa):
        weight[cls] += i2 - i1 + j2 - j1
        if cls == "code":
            minus += a[i1:i2]
            plus += b[j1:j2]
            code.append((i1, a[i1:i2][:8], b[j1:j2][:8]))
    moved = bool(code) and collections.Counter(minus) == collections.Counter(plus)
    renamed = bool(code) and not moved and isa.one_renaming(a, b)
    return Verdict(not code or moved or renamed, dict(weight), moved, renamed, code[:6], distance(a, b))


def code_size(isa, img, code: bytes, mask: bytes, addr: int, fill_forms) -> int:
    """Our function's code size: the end of its last instruction that is no alignment fill (CL pads a
    function's section with fill)."""
    lines = strip_fill(isa.listing(code, addr, mask, (img.base, img.end), fill_forms))
    return (lines[-1].addr + lines[-1].size - addr) if lines else len(code)


def listings(isa, img, code: bytes, mask: bytes, addr: int, orig_size: int, fill_forms):
    """(ours, the original's) listings at addr, trailing fill dropped; the original read up to its own code
    size (the walk's extent), so a shorter original does not bleed the next function into the diff."""
    rng = (img.base, img.end)
    A = strip_fill(isa.listing(code, addr, mask, rng, fill_forms))
    B = strip_fill(isa.listing(img.read(addr, orig_size), addr, None, rng, fill_forms))
    return A, B
