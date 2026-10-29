"""Setup rules (S.*): everything the image gives away before a line of source exists.

Every rule's docstring is its exact criterion; `dcp rules` prints them. Levels: a rule that reads the image
alone is proven; a rule that rests on a convention of the toolchain says which one and is derived.
"""
from __future__ import annotations

import struct
from collections import defaultdict

from ..ledger.fact import Fact, Kind, Level, Severity
from ..objfmt.coff import DIR32, DIR32NB, REL32, archive_members, archive_objects, is_import_member
from .engine import RuleContext, rule

P, D, O = Level.proven, Level.derived, Level.open


def _range_facts(ctx, what, ranges, level=P):
    for lo, hi in ranges:
        if hi > lo:
            yield ctx.fact(lo, hi, Kind.region, {"what": what}, level)


# ---------------------------------------------------------------------------------------------------- headers
@rule("S.headers", version="1", ceiling=P, outputs=("region",))
def headers(ctx: RuleContext):
    """The PE headers own [image base, image base + SizeOfHeaders): DOS header and stub, the Rich header where
    the linker wrote one (pe.rich), the PE signature, file and optional headers and the section table."""
    img = ctx.image
    lo, hi = img.base, img.base + img.headers_size
    rich = img.rich_range()
    if rich:
        yield from _range_facts(ctx, "pe.header", [(lo, rich[0]), (rich[1], hi)])
        yield ctx.fact(rich[0], rich[1], Kind.region, {"what": "pe.rich"}, P)
    else:
        yield ctx.fact(lo, hi, Kind.region, {"what": "pe.header"}, P)


@rule("S.sections", version="1", ceiling=P, outputs=("section", "region"))
def sections(ctx: RuleContext):
    """One section fact per entry of the section table, over [VirtualAddress, VirtualAddress + max(VirtualSize,
    SizeOfRawData)). File bytes past VirtualSize up to SizeOfRawData are file-alignment padding (region pad).
    The bytes between one section's end and the next section's start are not mapped (region unmapped)."""
    img = ctx.image
    secs = sorted(img.sections, key=lambda s: s.va)
    prev_end = img.base + img.headers_size
    for s in secs:
        if s.va > prev_end:
            yield ctx.fact(prev_end, s.va, Kind.region, {"what": "unmapped"}, P)
        yield ctx.fact(s.va, s.end, Kind.section,
                       {"name": s.name, "chars": s.chars, "raw_lo": s.raw_off, "raw_hi": s.raw_off + s.raw_size,
                        "code": s.code, "vsize": s.vsize, "rsize": s.raw_size}, P)
        if s.raw_size > s.vsize:
            yield ctx.fact(s.va + s.vsize, s.va + s.raw_size, Kind.region, {"what": "pad"}, P)
        prev_end = s.end
    if img.end > prev_end:
        yield ctx.fact(prev_end, img.end, Kind.region, {"what": "unmapped"}, P)


@rule("S.datadirs", version="1", ceiling=P, outputs=("region",))
def datadirs(ctx: RuleContext):
    """The data directories that are byte ranges of their own: base relocations (pe.reloc), resources
    (pe.rsrc), debug, TLS, load config, bound and delay imports, the COM descriptor. Import and export
    tables are walked by S.imports / S.exports, which know their exact extents."""
    img = ctx.image
    for dd in img.directories:
        if not dd.va or not dd.size or dd.name in ("import", "export", "iat", "security"):
            continue
        if img.section_of(dd.va) is None:
            continue
        yield ctx.fact(dd.va, dd.va + dd.size, Kind.region, {"what": "pe." + dd.name}, P)


@rule("S.imports", version="1", ceiling=P, outputs=("region", "symbol", "name"))
def imports(ctx: RuleContext):
    """The import machinery: descriptors (pe.import_desc), lookup tables (pe.ilt), hint/name strings and DLL
    names (pe.names), and one `iat` symbol per address-table slot, named DLL!symbol (or DLL!#ordinal), with
    the terminating zero slot of each table as pe.iat."""
    img = ctx.image
    r = img.import_descriptor_ranges()
    yield from _range_facts(ctx, "pe.import_desc", r["pe.import_desc"])
    yield from _range_facts(ctx, "pe.ilt", r["pe.ilt"])
    yield from _range_facts(ctx, "pe.names", sorted(set(r["pe.names"])))
    for lo, hi in r["pe.iat"]:
        yield ctx.fact(hi - 4, hi, Kind.region, {"what": "pe.iat"}, P)
    for imp in img.imports():
        yield ctx.fact(imp.slot, imp.slot + 4, Kind.symbol, {"skind": "iat", "name": imp.label, "extent": "proven"}, P)
        yield ctx.fact(imp.slot, imp.slot + 4, Kind.name, {"name": imp.label, "origin": "import"}, P)


@rule("S.exports", version="1", ceiling=P, outputs=("region", "start", "name"))
def exports(ctx: RuleContext):
    """The export directory with its address, name and ordinal tables and name strings (pe.export_*, pe.names),
    and for every exported address a function start plus its name (a forwarder names no start)."""
    img = ctx.image
    r = img.export_ranges()
    for what in ("pe.export_dir", "pe.eat", "pe.ent", "pe.eot"):
        yield from _range_facts(ctx, what, r[what])
    yield from _range_facts(ctx, "pe.names", sorted(set(r["pe.names"])))
    for e in img.exports():
        if e.forwarder:
            continue
        label = e.name or f"#{e.ordinal}"
        yield ctx.fact(e.va, e.va + 1, Kind.start, {"skind": "func", "how": "export"}, P)
        yield ctx.fact(e.va, e.va + 1, Kind.name, {"name": label, "origin": "export", "ordinal": e.ordinal}, P)


@rule("S.entry", version="1", ceiling=P, outputs=("start",))
def entry(ctx: RuleContext):
    """AddressOfEntryPoint is a function start."""
    img = ctx.image
    if img.entry:
        yield ctx.fact(img.entry, img.entry + 1, Kind.start, {"skind": "func", "how": "entry"}, P)


@rule("S.relocs", version="1", ceiling=P, outputs=("ref",))
def relocs(ctx: RuleContext):
    """One `reloc` reference per HIGHLOW entry of the base relocation directory: the 4 bytes at the site hold
    an absolute address of the image (`to`). For a dll this is the complete list of absolute operands in code
    and data."""
    img = ctx.image
    for site in img.relocations():
        yield ctx.fact(site, site + 4, Kind.ref, {"rkind": "reloc", "to": img.u32(site)}, P)


# ---------------------------------------------------------------------------------------------------- rich
@rule("S.rich", version="2", ceiling=D, outputs=("toolchain",), inputs=("libs",))
def rich(ctx: RuleContext):
    """The Rich header decoded with the toolchain's product table (Toolchain.rich_candidates): every entry with
    its tool, family, language, build and object count, and how many objects of the target's configured
    archives carry the same (prodid, build) in their @comp.id symbol (those entries are library objects the
    archives explain). The candidates are listed, never picked: every compiler entry is a compiler candidate,
    every linker entry a linker candidate; which one built the user's objects is the target's declaration
    ([[target]] compiler / linker), checked by C.toolchain. The fact spans the whole image; its level is
    derived (the product table is the community's reconstruction of Microsoft's ids)."""
    from ..objfmt.coff import comp_ids
    img, tc = ctx.image, ctx.project.toolchain
    entries = img.rich()
    if not entries:
        return
    yield ctx.fact(img.base, img.end, Kind.toolchain, tc.rich_candidates(entries, comp_ids(ctx.input("libs"))), D)


# ---------------------------------------------------------------------------------------------------- libraries
def _lib_sections(ctx):
    """[(lib name, Obj, Section)] of every code section with data of every object of the configured archives."""
    out = []
    for lib in ctx.input("libs"):
        for o in archive_objects(lib):
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


@rule("S.crt.code", version="1", ceiling=P, outputs=("symbol", "start", "name", "unit"), inputs=("libs",), needs=("S.relocs",))
def crt_code(ctx: RuleContext):
    """A code section of a library member is placed at the one position in a code section of the image where
    its bytes equal the image's with the relocation fields (DIR32 / DIR32NB / REL32, 4 bytes each) masked,
    every DIR32 site of the section is a base-relocation site of the image when the image has a relocation
    directory, and no base-relocation site falls on an unmasked byte. Sections shorter than 8 unmasked bytes
    are not searched. A section found at two or more positions is listed (warn S.crt.ambiguous) and places
    nothing. The placed section owns its bytes as one `func` symbol named by its first external symbol; every
    further symbol of the section is a start and a name; the unit is lib:<archive>/<member>."""
    img = ctx.image
    code_secs = [s for s in img.sections if s.code or s.executable]
    reloc_sites = {f.lo for f in ctx.facts(Kind.ref) if f.value["rkind"] == "reloc"}
    has_relocs = bool(reloc_sites)
    placed: list[tuple[int, int, str]] = []   # (lo, hi, label)

    def overlaps(lo, hi):
        return any(lo < b and a < hi for a, b, _ in placed)

    # sections with identical bytes and masks (memcpy / memmove, fopen / wfopen helpers, repeated helpers inside
    # one object) are one group: a group's hits are its members' code, the identity is proven only for a group
    # of one, else the names are listed (a|b) and the sources decide later.
    groups: dict[tuple[bytes, bytes], list] = {}
    for libname, o, sec in sorted(_lib_sections(ctx), key=lambda t: (t[0], t[1].name, t[2].num)):
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
            raw = img.data[s.raw_off:s.raw_off + s.raw_size]
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
                dir32_sites = {va + r.offset for r in sec0.relocs if r.type == DIR32}
                if not dir32_sites <= reloc_sites:
                    continue
                if any((site - va) < len(data) and not mask[site - va] for site in reloc_sites if va <= site < va + len(data)):
                    continue
            ok.append(va)
        if not ok:
            continue
        if len(ok) > len(members):
            yield ctx.conflict(Severity.warn, "S.crt.ambiguous", ok[0], ok[0] + len(data),
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
                if s.cls in (2, 3):
                    values[s.value].add(s.name)
        for va in ok:
            hi = va + len(data)
            if overlaps(va, hi):
                yield ctx.conflict(Severity.warn, "S.crt.duplicate", va, hi, f"{'|'.join(labels)} matches where another member is placed")
                continue
            placed.append((va, hi, "|".join(labels)))
            v = {"skind": "func", "name": name, "extent": "proven", "unit": unit}
            if len(members) > 1:
                v["candidates"] = len(members)
            yield ctx.fact(va, hi, Kind.symbol, v, P)
            yield ctx.fact(va, hi, Kind.unit, {"tu": unit, "lib": members[0][0]}, P)
            for value, ns in sorted(values.items()):
                a = va + value
                yield ctx.fact(a, a + 1, Kind.start, {"skind": "func", "how": "crt"}, P)
                yield ctx.fact(a, a + 1, Kind.name, {"name": "|".join(sorted(ns)), "origin": "lib", "unit": unit}, P)


@rule("S.crt.refs", version="1", ceiling=P, outputs=("name", "start"), inputs=("libs",), needs=("S.crt.code",))
def crt_refs(ctx: RuleContext):
    """Every relocation of a placed library section names the address it resolves to: a DIR32 site holds the
    symbol's address plus the addend the object stores at the site, a REL32 site the displacement to it. Symbols the member defines itself are
    checked (their address must be where S.crt.code placed them); symbols it imports from elsewhere get a
    name fact at the resolved address: the user's entry (_DllMain@12, _main, _WinMain@16), CRT data of other
    members, and so on. Two sites that resolve one symbol to two addresses are a conflict."""
    img = ctx.image
    placed = {}
    for f in ctx.facts(Kind.symbol):
        if f.value.get("skind") == "func" and f.value.get("unit", "").startswith("lib:"):
            placed[f.value["unit"] + ":" + f.value["name"]] = f
    by_unit = defaultdict(list)
    for f in placed.values():
        by_unit[f.value["unit"]].append(f)
    resolved: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))   # symbol -> address -> sites
    functions: set[str] = set()
    for lib in ctx.input("libs"):
        for o in archive_objects(lib):
            unit = f"lib:{lib.name}/{o.name}"
            if unit not in by_unit:
                continue
            for sec in o.code_sections:
                # find where this section was placed: by its first external symbol name
                exts = [s for s in sec.syms if s.external]
                name = exts[0].name if exts else (sec.syms[0].name if sec.syms else None)
                f = placed.get(f"{unit}:{name}")
                if f is None or f.hi - f.lo != sec.size:
                    continue
                for r in sec.relocs:
                    sym = o.symbols.get(r.symbol_index)
                    if sym is None:
                        continue
                    site = f.lo + r.offset
                    addend = struct.unpack_from("<I", sec.data, r.offset)[0]   # the dword the object holds at the site
                    if r.type == DIR32:
                        target = (img.u32(site) - addend) & 0xffffffff
                    elif r.type == REL32:
                        target = (site + 4 + img.u32(site) - addend) & 0xffffffff
                    else:
                        continue
                    if sym.defined:
                        continue
                    if sym.cls == 2 and sym.secnum == 0 and not sym.name.startswith("__imp_"):
                        resolved[sym.name][target] += 1
                        if sym.function:
                            functions.add(sym.name)
    for name, addrs in sorted(resolved.items()):
        if len(addrs) > 1:
            yield ctx.conflict(Severity.bug, "S.crt.refs", min(addrs), min(addrs) + 1,
                               f"{name} resolves to {len(addrs)} addresses: " + ", ".join(f"{a:#x}x{n}" for a, n in sorted(addrs.items())))
            continue
        (a, n), = addrs.items()
        if not img.in_image(a):
            continue
        yield ctx.fact(a, a + 1, Kind.name, {"name": name, "origin": "lib", "sites": n}, P)
        if name in functions:
            yield ctx.fact(a, a + 1, Kind.start, {"skind": "func", "how": "libref"}, P)


@rule("S.crt.data", version="1", ceiling=P, outputs=("symbol", "name", "unit"), inputs=("libs",), needs=("S.crt.code",))
def crt_data(ctx: RuleContext):
    """A data section of a placed library member sits where that member's own DIR32 relocations into it point:
    the dword at a placed code site minus the referenced symbol's offset in its section is the section's
    base. Every site must give the same base (else a conflict and nothing is placed); the placed section owns
    [base, base + size) as a `crt.data` symbol named by its first symbol."""
    img = ctx.image
    placed = {}
    for f in ctx.facts(Kind.symbol):
        if f.value.get("skind") == "func" and f.value.get("unit", "").startswith("lib:"):
            placed[f.value["unit"] + ":" + f.value["name"]] = f
    done: list[tuple[int, int]] = []
    for lib in ctx.input("libs"):
        for o in archive_objects(lib):
            unit = f"lib:{lib.name}/{o.name}"
            bases: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))   # secnum -> base -> sites
            for sec in o.code_sections:
                exts = [s for s in sec.syms if s.external]
                name = exts[0].name if exts else (sec.syms[0].name if sec.syms else None)
                f = placed.get(f"{unit}:{name}")
                if f is None or f.hi - f.lo != sec.size:
                    continue
                for r in sec.relocs:
                    if r.type != DIR32:
                        continue
                    sym = o.symbols.get(r.symbol_index)
                    if sym is None or not sym.defined or sym.section is None or sym.section.code or sym.section.discard:
                        continue
                    addend = struct.unpack_from("<I", sec.data, r.offset)[0]
                    bases[sym.secnum][(img.u32(f.lo + r.offset) - addend - sym.value) & 0xffffffff] += 1
            for secnum, bs in sorted(bases.items()):
                sec = o.sections[secnum]
                if len(bs) > 1:
                    yield ctx.conflict(Severity.warn, "S.crt.data", min(bs), min(bs) + 1,
                                       f"{unit} {sec.name}#{secnum} has {len(bs)} bases: " + ", ".join(f"{b:#x}x{n}" for b, n in sorted(bs.items())))
                    continue
                (base, n), = bs.items()
                if sec.size == 0 or not img.in_image(base):
                    continue
                lo, hi = base, base + sec.size
                if any(lo < b and a < hi for a, b in done):
                    yield ctx.conflict(Severity.warn, "S.crt.data", lo, hi, f"{unit} {sec.name}#{secnum} overlaps another placed data section")
                    continue
                done.append((lo, hi))
                first = next((s for s in sec.syms if s.cls in (2, 3)), None)
                name = first.name if first else f"{o.name}:{sec.name}#{secnum}"
                yield ctx.fact(lo, hi, Kind.symbol, {"skind": "crt.data", "name": name, "extent": "proven", "unit": unit,
                                                     "section": sec.name, "bss": sec.data is None}, P)
                yield ctx.fact(lo, hi, Kind.unit, {"tu": unit, "lib": lib.name}, P)
                for s in sec.syms:
                    if s.cls in (2, 3):
                        yield ctx.fact(lo + s.value, lo + s.value + 1, Kind.name, {"name": s.name, "origin": "lib", "unit": unit}, P)


@rule("S.thunk", version="2", ceiling=D, outputs=("symbol", "name"), needs=("S.imports", "S.crt.code"))
def thunk(ctx: RuleContext):
    """`FF 25 <address of an import address-table slot>` (6 bytes, `jmp dword ptr [slot]`) in a code section,
    outside every placed library section, is a candidate. The same 6 bytes are what VC6 compiles for `return
    f(...)` when f is a dllimport function, as the last instruction of a function or as a whole function, so a
    candidate is an import thunk (named after the slot) only where LINK's layout makes it a library
    contribution: it lies at or after the start of the first placed library section (convention: LINK places
    every library contribution after the objects of the command line), or another candidate adjoins it
    (convention: LINK packs the 6-byte thunks of an import library back to back; VC6 starts every compiled
    function at a 16-byte boundary). Every other candidate is compiled code, which the walk reaches."""
    img = ctx.image
    slots = {f.lo: f.value["name"] for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "iat"}
    crt = [(f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "func"]
    first_lib = min((a for a, _ in crt), default=None)
    cands = []
    for s in img.sections:
        if not (s.code or s.executable):
            continue
        raw = img.data[s.raw_off:s.raw_off + s.raw_size]
        p = raw.find(b"\xff\x25")
        while p >= 0:
            if p + 6 <= len(raw):
                slot = struct.unpack_from("<I", raw, p + 2)[0]
                va = s.va + p
                if slot in slots and not any(a <= va < b for a, b in crt):
                    cands.append((va, slots[slot]))
            p = raw.find(b"\xff\x25", p + 1)
    at = {va for va, _ in cands}
    for va, name in cands:
        if (first_lib is not None and va >= first_lib) or va - 6 in at or va + 6 in at:
            yield ctx.fact(va, va + 6, Kind.symbol, {"skind": "thunk", "name": name, "extent": "proven"}, D)
            yield ctx.fact(va, va + 1, Kind.name, {"name": "thunk:" + name, "origin": "import"}, D)


@rule("S.entry.user", version="1", ceiling=D, outputs=("name",), needs=("S.crt.refs", "S.entry", "S.codewalk"))
def entry_user(ctx: RuleContext):
    """The user entry: when the CRT names the symbol the CRT start-up calls (_DllMain@12, _main, _WinMain@16
    through S.crt.refs), that name is the user's entry function. Reported as its C spelling (DllMain, main,
    WinMain) for the layout."""
    tc = ctx.project.toolchain
    user = {"_DllMain@12": "DllMain", "_main": "main", "_WinMain@16": "WinMain", "_wmain": "wmain", "_wWinMain@16": "wWinMain"}
    for f in ctx.facts(Kind.name):
        if f.value.get("origin") == "lib" and f.value["name"] in user:
            yield ctx.fact(f.lo, f.lo + 1, Kind.name, {"name": user[f.value["name"]], "origin": "entry"}, D)


@rule("S.strings", version="2", ceiling=D, outputs=("symbol",), needs=("S.relocs", "S.sections", "S.crt.data"))
def strings(ctx: RuleContext):
    """A relocation target in a data section whose bytes are at least 4 printable ASCII characters (0x20..0x7e,
    tab, CR, LF) followed by NUL is a string literal: the start is where the pointer points (proven), the extent
    runs to the first NUL (convention: C strings are NUL-terminated). A target inside an already claimed
    string is an inner reference, not a new string; bytes a placed library data section owns are that
    section's (its strings are named there)."""
    img = ctx.image
    data_secs = [s for s in img.sections if not (s.code or s.executable)]
    targets = sorted({f.value["to"] for f in ctx.facts(Kind.ref) if f.value["rkind"] == "reloc"})
    placed = sorted((f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "crt.data")
    last_hi = 0
    for t in targets:
        if t < last_hi or any(a <= t < b for a, b in placed):
            continue
        s = img.section_of(t)
        if s is None or s not in data_secs:
            continue
        o = img.off(t)
        if o is None:
            continue
        e = img.data.find(b"\0", o, min(o + 4096, s.raw_off + s.raw_size))
        if e < 0 or e - o < 4:
            continue
        run = img.data[o:e]
        if not all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in run):
            continue
        last_hi = t + len(run) + 1
        text = run.decode("ascii")
        yield ctx.fact(t, last_hi, Kind.symbol, {"skind": "string", "extent": "derived", "text": text[:60]}, D)


@rule("S.fill", version="1", ceiling=D, outputs=("symbol",),
      needs=("S.sections", "S.crt.code", "S.thunk", "S.codewalk", "S.imports"))
def fill(ctx: RuleContext):
    """An unclaimed run of a code section that decodes entirely into the toolchain's alignment fill forms
    (VC6: 90, CC, 8B FF, 8D 49 00) and ends at a claimed byte or the section's end is fill. One other byte
    makes the whole run not fill."""
    img, tc = ctx.image, ctx.project.toolchain
    forms = tuple(sorted(tc.fill_forms, key=len, reverse=True))
    for s in img.sections:
        if not (s.code or s.executable):
            continue
        claimed = sorted((f.lo, f.hi) for f in ctx.facts(Kind.symbol, s.va, s.end))
        claimed += [(f.lo, f.hi) for f in ctx.facts(Kind.region, s.va, s.end)]
        claimed.sort()
        pos = s.va
        gaps = []
        for a, b in claimed:
            if a > pos:
                gaps.append((pos, a))
            pos = max(pos, b)
        if s.va + s.vsize > pos:
            gaps.append((pos, s.va + s.vsize))
        for lo, hi in gaps:
            b = img.read(lo, hi - lo)
            i = 0
            ok = True
            while i < len(b):
                for f in forms:
                    if b.startswith(f, i):
                        i += len(f)
                        break
                else:
                    ok = False
                    break
            if ok and len(b):
                yield ctx.fact(lo, hi, Kind.symbol, {"skind": "fill", "extent": "derived"}, D)


@rule("S.unknown", version="1", ceiling=O, outputs=("symbol",), needs=("kind:symbol", "kind:region", "S.sections"))
def unknown(ctx: RuleContext):
    """Every mapped byte of a section that no symbol and no region claims is unknown: unknown.code in a code
    section, unknown.data elsewhere. This is the catch-all that makes the byte map total; it claims nothing
    about the bytes."""
    img = ctx.image
    for s in img.sections:
        claimed = sorted({(f.lo, f.hi) for f in ctx.facts(Kind.symbol, s.va, s.end)} | {(f.lo, f.hi) for f in ctx.facts(Kind.region, s.va, s.end)})
        pos = s.va
        sk = "unknown.code" if (s.code or s.executable) else "unknown.data"
        for a, b in claimed:
            if a > pos:
                yield ctx.fact(pos, a, Kind.symbol, {"skind": sk, "extent": "open"}, O)
            pos = max(pos, b)
        if s.end > pos:
            yield ctx.fact(pos, s.end, Kind.symbol, {"skind": sk, "extent": "open"}, O)
