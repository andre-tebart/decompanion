"""The compare: one compiled function against the original's bytes (lifted from the first attempt's
core/build.py compare(), with the DLL aid and the tail check added).

Masked byte compare: our function's bytes (its section from the function symbol on, ObjectFormat
function_code) against the image's bytes at the function's address, every byte a relocation of ours rewrites
masked. The DLL aid, when the image carries base relocations (the dll's complete list of absolute address
fields): every absolute relocation site of ours is a base-relocation site of the image, and the image holds
as many base relocations inside the function's extent as we have absolute relocations (`relocs 7/7`). The tail
check: the original does not continue after our last byte (the bytes up to the next function start are
alignment fill of the toolchain's forms, or there are none).

Objects are read once per process per object hash.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path

from ..objfmt.base import ABSOLUTE

_objs: dict[str, object] = {}


def read_object(project, obj_hash: str):
    """The Obj of build/obj/<obj_hash>.obj (memoised per process), None when the file is missing."""
    o = _objs.get(obj_hash)
    if o is None:
        p = Path(project.root) / "build" / "obj" / f"{obj_hash}.obj"
        if not p.exists():
            return None
        o = _objs[obj_hash] = project.objfmt.read_object(p)
    return o


def objects(project, tus: dict) -> dict:
    """unit -> Obj of every compiled unit (tu rows with ok and an object on disk)."""
    out = {}
    for unit, row in tus.items():
        if row["ok"] and row["obj_hash"]:
            o = read_object(project, row["obj_hash"])
            if o is not None:
                out[unit] = o
    return out


def function_index(obj, tc) -> dict[str, object]:
    """C name -> function symbol of an object (Toolchain.undecorate)."""
    out = {}
    for s in obj.functions():
        out.setdefault(tc.undecorate(s.name), s)
    return out


def is_fill(data: bytes, forms) -> bool:
    """Every byte of data belongs to a run of the toolchain's fill forms (empty: True)."""
    forms = sorted(forms, key=len, reverse=True)
    i = 0
    while i < len(data):
        for f in forms:
            if data.startswith(f, i):
                i += len(f)
                break
        else:
            return False
    return True


@dataclass
class Compared:
    addr: int
    size: int
    ours: bytes
    mask: bytes
    orig: bytes
    diffs: list = field(default_factory=list)       # offsets of differing unmasked bytes
    tail_ok: bool = True
    tail: tuple = (0, 0)                             # [our end, next start) of the original
    abs_ours: int = 0                                # our absolute relocation sites
    abs_image: int | None = None                     # base relocations of the image inside the extent (None: no list)
    sites_ok: bool = True                            # every absolute site of ours is a base relocation site
    missing_sites: list = field(default_factory=list)

    @property
    def bytes_equal(self) -> bool:
        return not self.diffs

    @property
    def aid(self) -> str:
        """`relocs ours/image` for a dll, `-` without base relocations."""
        return "-" if self.abs_image is None else f"{self.abs_ours}/{self.abs_image}"

    @property
    def aid_ok(self) -> bool:
        return self.abs_image is None or (self.sites_ok and self.abs_ours == self.abs_image)

    @property
    def matched(self) -> bool:
        return self.bytes_equal and self.tail_ok and self.aid_ok

    def why(self) -> str:
        """Why the function is not a match ('' when it is)."""
        out = []
        if self.diffs:
            out.append(f"{len(self.diffs)} of {self.size} bytes differ, the first at +{self.diffs[0]:#x}")
        if not self.tail_ok:
            out.append(f"the original continues after our end: {self.tail[0]:#x}..{self.tail[1]:#x} is no fill")
        if self.abs_image is not None and not self.sites_ok:
            out.append("absolute relocation sites of ours that are no base relocation of the image: "
                       + ",".join(f"{a:#x}" for a in self.missing_sites[:6]))
        if self.abs_image is not None and self.sites_ok and self.abs_ours != self.abs_image:
            out.append(f"relocs {self.abs_ours}/{self.abs_image}: the image relocates fields we do not")
        return "; ".join(out)


def compare(img, code, addr: int, reloc_sites: list[int] | None, next_start: int, fill_forms) -> Compared:
    """Compare a FunctionCode with the image at addr. `reloc_sites`: the sorted base-relocation sites of the
    image (None when the image has none); `next_start`: the next function start after addr (the end of the
    original's slot)."""
    n = code.size
    orig = img.read(addr, n)
    c = Compared(addr, n, code.data, code.mask, orig)
    c.diffs = [k for k in range(n) if not code.mask[k] and code.data[k] != orig[k]]
    end = addr + n
    if next_start > end:
        c.tail = (end, next_start)
        c.tail_ok = is_fill(img.read(end, next_start - end), fill_forms)
    elif next_start < end:
        c.tail = (next_start, end)
        c.tail_ok = False
    abs_sites = [addr + off for off, r, _ in code.relocs if r.kind == ABSOLUTE]
    c.abs_ours = len(abs_sites)
    if reloc_sites is not None:
        lo = bisect.bisect_left(reloc_sites, addr)
        hi = bisect.bisect_left(reloc_sites, end)
        c.abs_image = hi - lo
        have = set(reloc_sites[lo:hi])
        c.missing_sites = [s for s in abs_sites if s not in have]
        c.sites_ok = not c.missing_sites
    return c


def aligned_sites(isa, c: Compared, sites) -> set[int]:
    """The offsets of `sites` ((offset, width) of our relocated fields) that line up with the original's code:
    our bytes and the original's bytes at the function's address, each decoded straight from the first byte
    (Isa.disasm), both have an instruction starting at the same offset that holds the field, of the same size,
    and the two agree in every byte our relocations do not mask. Only there does the original's field hold
    what our field stands for; anywhere else it holds unrelated bytes. A match lines up everywhere."""
    if c.matched:
        return {off for off, _ in sites}
    ours = isa.disasm(bytes(c.ours), c.addr)
    starts = [ln.addr - c.addr for ln in ours]
    theirs = {ln.addr - c.addr: ln.size for ln in isa.disasm(bytes(c.orig), c.addr)}
    out = set()
    for off, width in sites:
        i = bisect.bisect_right(starts, off) - 1
        if i < 0:
            continue
        o, n = starts[i], ours[i].size
        if off + width > o + n or theirs.get(o) != n:
            continue
        if all(c.mask[k] or c.ours[k] == c.orig[k] for k in range(o, o + n)):
            out.add(off)
    return out
