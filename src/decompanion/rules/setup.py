"""Setup rules (S.*): everything the image gives away before a line of source exists.

Every rule's docstring is its exact criterion; `dcp rules` prints them. Levels: a rule that reads the image
alone is proven; a rule that rests on a convention of the toolchain says which one and is derived.

The rules know no container, object format, toolchain or instruction set: they ask the image (image/base.py),
the objects of the archives (objfmt/base.py: relocation kinds absolute / relative / absolute-rva) and the
toolchain (toolchains/base.py). Docstrings cite the VC6 / PE32 / COFF plugin's answers as the example.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..ledger.fact import Level
from ..objfmt.base import ABSOLUTE
from .engine import RuleContext, rule

P, D, O = Level.proven, Level.derived, Level.open


# ---------------------------------------------------------------------------------------------------- headers
# ---------------------------------------------------------------------------------------------------- rich
# ---------------------------------------------------------------------------------------------------- libraries
def lib_sections(objfmt, libs) -> list:
    """[(lib name, Obj, Section)] of every code section with data of every object of the archives `libs`."""
    out = []
    for lib in libs:
        for o in objfmt.archive_objects(lib):
            for s in o.code_sections:
                out.append((lib.name, o, s))
    return out


def _longest_run(mask: bytes) -> tuple[int, int]:
    """(offset, length) of the longest unmasked run."""
    best = (0, 0)
    i, n = 0, len(mask)
    while i < n:
        if mask[i]:
            i += 1
            continue
        j = i
        while j < n and not mask[j]:
            j += 1
        if j - i > best[1]:
            best = (i, j - i)
        i = j
    return best


def _masked_equal(a: bytes, b: bytes, mask: bytes) -> bool:
    return all(m or x == y for x, y, m in zip(a, b, mask))


@dataclass(frozen=True)
class Placement:
    """One placed group of identical library sections (place_members)."""
    lo: int
    hi: int
    name: str           # the first external symbol of the section, `a|b` for a group of several members
    unit: str           # lib:<archive>/<member>, `|`-joined for a group
    lib: str            # the archive of the group's first member
    members: int        # the members of the group (1: the identity is proven)
    values: tuple       # ((offset, (names...)), ...) every named symbol inside the section


def place_members(img, sections, reloc_sites: set[int]):
    """S.crt.code's search over `sections` (lib_sections): yields Placement for every placed group, and
    ("ambiguous" | "duplicate", lo, hi, message) for a group that places nothing (its criterion: S.crt.code's
    docstring). `dcp libs candidates` runs the same search per archive."""
    code_secs = [s for s in img.sections if s.holds_code]
    has_relocs = bool(reloc_sites)
    placed: list[tuple[int, int, str]] = []   # (lo, hi, label)

    def overlaps(lo, hi):
        return any(lo < b and a < hi for a, b, _ in placed)

    # sections with identical bytes and masks (memcpy / memmove, fopen / wfopen helpers, repeated helpers inside
    # one object) are one group: a group's hits are its members' code, the identity is proven only for a group
    # of one, else the names are listed (a|b) and the sources decide later.
    groups: dict[tuple[bytes, bytes], list] = {}
    for libname, o, sec in sorted(sections, key=lambda t: (t[0], t[1].name, t[2].num)):
        data, mask = sec.data, sec.mask()
        if sum(1 for m in mask if not m) < 8:
            continue
        groups.setdefault((data, mask), []).append((libname, o, sec))

    def sec_name(sec):
        exts = [s for s in sec.syms if s.external]
        first = exts[0] if exts else (sec.syms[0] if sec.syms else None)
        return first.name if first else f"{sec.obj.name}:{sec.name}#{sec.num}"

    for (data, mask), members in sorted(groups.items(), key=lambda kv: (kv[1][0][0], kv[1][0][1].name, kv[1][0][2].num)):
        aoff, alen = _longest_run(mask)
        anchor = data[aoff:aoff + alen]
        hits = []
        for s in code_secs:
            raw = img.section_data(s)
            p = raw.find(anchor)
            while p >= 0:
                start = p - aoff
                if 0 <= start and start + len(data) <= len(raw) and _masked_equal(raw[start:start + len(data)], data, mask):
                    hits.append(s.va + start)
                p = raw.find(anchor, p + 1)
        hits = sorted(set(hits))
        sec0 = members[0][2]
        labels = [f"{lib}/{o.name}:{sec.name}#{sec.num}" for lib, o, sec in members]
        ok = []
        for va in hits:
            if has_relocs:
                abs_sites = {va + r.offset for r in sec0.relocs if r.kind == ABSOLUTE}
                if not abs_sites <= reloc_sites:
                    continue
                if any((site - va) < len(data) and not mask[site - va] for site in reloc_sites if va <= site < va + len(data)):
                    continue
            ok.append(va)
        if not ok:
            continue
        if len(ok) > len(members):
            yield ("ambiguous", ok[0], ok[0] + len(data),
                   f"{'|'.join(labels)} matches at {len(ok)} positions: " + ", ".join(f"{x:#x}" for x in ok[:6]))
            continue
        names = sorted({sec_name(sec) for _, _, sec in members})
        units = sorted({f"lib:{lib}/{o.name}" for lib, o, _ in members})
        name = names[0] if len(names) == 1 else "|".join(names)
        unit = units[0] if len(units) == 1 else "|".join(units)
        # symbols inside the section: a start at every value; the name where every member agrees
        values: dict[int, set[str]] = defaultdict(set)
        for _, _, sec in members:
            for s in sec.syms:
                if s.named:
                    values[s.value].add(s.name)
        for va in ok:
            hi = va + len(data)
            if overlaps(va, hi):
                yield ("duplicate", va, hi, f"{'|'.join(labels)} matches where another member is placed")
                continue
            placed.append((va, hi, "|".join(labels)))
            yield Placement(va, hi, name, unit, members[0][0], len(members),
                            tuple((value, tuple(sorted(ns))) for value, ns in sorted(values.items())))

