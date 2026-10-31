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

from ..ledger.fact import Fact, Kind, Level, Severity
from ..objfmt.base import ABSOLUTE, RELATIVE
from .engine import RuleContext, rule

P, D, O = Level.proven, Level.derived, Level.open


# ---------------------------------------------------------------------------------------------------- headers
@rule("S.headers", version="1", ceiling=P, outputs=("region",), native=True)
def headers(ctx: RuleContext):
    """The image format's headers own their bytes, one region each as the format names them
    (Image.header_regions; PE32: [image base, image base + SizeOfHeaders) is DOS header and stub, PE
    signature, file and optional headers and section table as pe.header, the Rich header where the linker
    wrote one as pe.rich)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S.sections", version="1", ceiling=P, outputs=("section", "region"), native=True)
def sections(ctx: RuleContext):
    """One section fact per entry of the section table, over [VirtualAddress, VirtualAddress + max(VirtualSize,
    SizeOfRawData)). File bytes past VirtualSize up to SizeOfRawData are file-alignment padding (region pad).
    The bytes between one section's end and the next section's start are not mapped (region unmapped)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S.datadirs", version="1", ceiling=P, outputs=("region",), native=True)
def datadirs(ctx: RuleContext):
    """The directories of the image format that are byte ranges of their own inside a section
    (Image.directory_regions; PE32: base relocations, resources, debug, TLS, load config, bound and delay
    imports, the COM descriptor, as pe.<directory>). Import and export tables are walked by S.imports /
    S.exports, which know their exact extents."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S.imports", version="1", ceiling=P, outputs=("region", "symbol", "name"), native=True)
def imports(ctx: RuleContext):
    """The import machinery as regions (Image.import_regions; PE32: descriptors pe.import_desc, lookup tables
    pe.ilt, hint/name strings and DLL names pe.names, the terminating zero slot of each address table
    pe.iat), and one `iat` symbol per address-table slot (an address wide), named DLL!symbol (or
    DLL!#ordinal)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S.exports", version="1", ceiling=P, outputs=("region", "start", "name"), native=True)
def exports(ctx: RuleContext):
    """The export machinery as regions (Image.export_regions; PE32: the export directory with its address, name
    and ordinal tables and name strings, pe.export_*, pe.names), and for every exported address a function
    start plus its name (a forwarder names no start)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S.entry", version="1", ceiling=P, outputs=("start",), native=True)
def entry(ctx: RuleContext):
    """AddressOfEntryPoint is a function start."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S.relocs", version="1", ceiling=P, outputs=("ref",), native=True)
def relocs(ctx: RuleContext):
    """One `reloc` reference per absolute relocation site of the image (Image.relocations; PE32: every HIGHLOW
    entry of the base relocation directory): the address-wide field at the site holds an absolute address of
    the image (`to`). For a dll this is the complete list of absolute operands in code and data."""
    return ()                                      # native: native/dcp_core/src/setup.rs


# ---------------------------------------------------------------------------------------------------- rich
@rule("S.rich", version="2", ceiling=D, outputs=("toolchain",), inputs=("archives",))
def rich(ctx: RuleContext):
    """The Rich header decoded with the toolchain's product table (Toolchain.rich_candidates): every entry with
    its tool, family, language, build and object count, and how many objects of the target's configured
    archives carry the same (prodid, build) in their tool stamp (ObjectFormat.tool_stamps decoded by
    Toolchain.archive_tools; COFF / VC6: the @comp.id symbol) (those entries are library objects the archives
    explain; before the archives are declared every count is 0). The candidates are listed, never picked: every
    compiler entry is a compiler candidate, every linker entry a linker candidate; which one built the user's
    objects is the target's declaration ([[target]] compiler / linker), checked by C.toolchain. The fact spans
    the whole image; its level is derived (the product table is the community's reconstruction of Microsoft's
    ids)."""
    img, tc = ctx.image, ctx.project.toolchain
    entries = img.rich()
    if not entries:
        return
    tools = tc.archive_tools(ctx.project.objfmt.tool_stamps(ctx.input("archives")))
    yield ctx.fact(img.base, img.end, Kind.toolchain, tc.rich_candidates(entries, tools), D)


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


@rule("S.crt.code", version="1", ceiling=P, outputs=("symbol", "start", "name", "unit"), inputs=("libs",), needs=("S.relocs",),
      helpers=(lib_sections, _longest_run, _masked_equal, place_members))
def crt_code(ctx: RuleContext):
    """A code section of a library member is placed at the one position in a code section of the image where
    its bytes equal the image's with the relocation fields masked (Section.mask: every byte a relocation of
    a known kind rewrites; COFF: DIR32 / DIR32NB / REL32, 4 bytes each), every absolute relocation site of
    the section is a base-relocation site of the image when the image has a relocation directory, and no
    base-relocation site falls on an unmasked byte. Sections shorter than 8 unmasked bytes are not searched.
    A section found at two or more positions is listed (warn S.crt.ambiguous) and places nothing. The placed
    section owns its bytes as one `func` symbol named by its first external symbol; every further named
    symbol of the section (external or file-static) is a start and a name; the unit is lib:<archive>/<member>.
    Waits for the declared archives (`dcp libs declare`)."""
    reloc_sites = {f.lo for f in ctx.facts(Kind.ref) if f.value["rkind"] == "reloc"}
    for pl in place_members(ctx.image, lib_sections(ctx.project.objfmt, ctx.input("libs")), reloc_sites):
        if not isinstance(pl, Placement):
            what, lo, hi, msg = pl
            yield ctx.conflict(Severity.warn, f"S.crt.{what}", lo, hi, msg)
            continue
        v = {"skind": "func", "name": pl.name, "extent": "proven", "unit": pl.unit}
        if pl.members > 1:
            v["candidates"] = pl.members
        yield ctx.fact(pl.lo, pl.hi, Kind.symbol, v, P)
        yield ctx.fact(pl.lo, pl.hi, Kind.unit, {"tu": pl.unit, "lib": pl.lib}, P)
        for value, ns in pl.values:
            a = pl.lo + value
            yield ctx.fact(a, a + 1, Kind.start, {"skind": "func", "how": "crt"}, P)
            yield ctx.fact(a, a + 1, Kind.name, {"name": "|".join(ns), "origin": "lib", "unit": pl.unit}, P)


@rule("S.lib.data", version="2", ceiling=P, outputs=("symbol", "name", "unit"), inputs=("libs",), needs=("S.crt.code", "S.crt.data"))
def lib_data(ctx: RuleContext):
    """A data-only member of an archive (no code section; S.crt.data places only the data that placed code
    points to) is placed by content: an initialised data section without relocations, at least 8 bytes long
    with at least 8 nonzero bytes, whose bytes occur exactly once in the image's initialised data sections, and
    not over a section already placed (and no .idata$* section: the PE rules own the import tables), owns
    [that address, + size) as a `crt.data` symbol, its member a `unit`
    fact {tu, lib}, every named symbol a name (a GUID of an interface-id library, a CRT string table). Two
    members with the same bytes at one address are one placement (the first member; `candidates` counts them)."""
    img = ctx.image
    raws = [(s, img.section_data(s)) for s in img.sections if not s.holds_code and not s.uninitialized]
    done = sorted((f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "crt.data")
    seen: dict[tuple[int, bytes], dict] = {}
    pending = []
    for lib in ctx.input("libs"):
        for o in ctx.project.objfmt.archive_objects(lib):
            if o.code_sections:
                continue
            for sec in o.sections[1:]:
                if sec.code or sec.discard or sec.data is None or sec.relocs or sec.size < 8 or sec.name.startswith(".idata"):
                    continue                        # .idata$*: an import member's tables, the image's import region
                data = bytes(sec.data)
                if sum(1 for b in data if b) < 8:
                    continue
                hits = []
                for s, raw in raws:
                    k = raw.find(data)
                    while k >= 0 and len(hits) < 2:
                        hits.append(s.va + k)
                        k = raw.find(data, k + 1)
                if len(hits) != 1:
                    continue
                lo, hi = hits[0], hits[0] + sec.size
                key = (lo, data)
                if key in seen:
                    seen[key]["candidates"] += 1
                    continue
                if any(lo < b and a < hi for a, b in done):
                    continue
                unit = f"lib:{lib.name}/{o.name}"
                first = next((s for s in sec.syms if s.named), None)
                v = {"skind": "crt.data", "name": first.name if first else f"{o.name}:{sec.name}", "extent": "proven",
                     "unit": unit, "section": sec.name, "bss": False, "how": "content", "candidates": 1}
                seen[key] = v
                done.append((lo, hi))
                pending.append((lo, hi, v, unit, lib.name, [s for s in sec.syms if s.named]))
    for lo, hi, v, unit, libname, named in pending:          # after every member: `candidates` is final
        yield ctx.fact(lo, hi, Kind.symbol, v, P)
        yield ctx.fact(lo, hi, Kind.unit, {"tu": unit, "lib": libname}, P)
        for s in named:
            yield ctx.fact(lo + s.value, lo + s.value + 1, Kind.name, {"name": s.name, "origin": "lib", "unit": unit}, P)


@rule("S.crt.refs", version="1", ceiling=P, outputs=("name", "start"), inputs=("libs",), needs=("S.crt.code",))
def crt_refs(ctx: RuleContext):
    """Every absolute or relative relocation of a placed library section names the address it resolves to
    (Reloc.resolve: an absolute site holds the symbol's address plus the addend the object stores at the
    site, a relative site the displacement to it; COFF: DIR32 / REL32). Symbols the member defines itself
    are not named again (S.crt.code placed them); symbols it references and another object defines (not
    through an import address-table slot) get a name fact at the resolved address: the user's entry
    (_DllMain@12, _main, _WinMain@16), CRT data of other members, and so on; a start too when the symbol is a
    function. Two sites that resolve one symbol to two addresses are a conflict."""
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
        for o in ctx.project.objfmt.archive_objects(lib):
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
                    if r.kind not in (ABSOLUTE, RELATIVE):
                        continue
                    site = f.lo + r.offset
                    target = r.resolve(site, img.read(site, r.width), sec.addend(r))
                    if sym.defined:
                        continue
                    if sym.unresolved and not sym.dllimport:
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
    """A data section of a placed library member sits where that member's own absolute relocations into it
    point (COFF: DIR32): the address a placed code site resolves to (Reloc.resolve) minus the referenced
    symbol's offset in its section is the section's base. Every site must give the same base (else a
    conflict and nothing is placed); the placed section owns [base, base + size) as a `crt.data` symbol named
    by its first named symbol (external or file-static), and every named symbol is a name."""
    img = ctx.image
    placed = {}
    for f in ctx.facts(Kind.symbol):
        if f.value.get("skind") == "func" and f.value.get("unit", "").startswith("lib:"):
            placed[f.value["unit"] + ":" + f.value["name"]] = f
    done: list[tuple[int, int]] = []
    for lib in ctx.input("libs"):
        for o in ctx.project.objfmt.archive_objects(lib):
            unit = f"lib:{lib.name}/{o.name}"
            bases: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))   # secnum -> base -> sites
            for sec in o.code_sections:
                exts = [s for s in sec.syms if s.external]
                name = exts[0].name if exts else (sec.syms[0].name if sec.syms else None)
                f = placed.get(f"{unit}:{name}")
                if f is None or f.hi - f.lo != sec.size:
                    continue
                for r in sec.relocs:
                    if r.kind != ABSOLUTE:
                        continue
                    sym = o.symbols.get(r.symbol_index)
                    if sym is None or not sym.defined or sym.section is None or sym.section.code or sym.section.discard:
                        continue
                    site = f.lo + r.offset
                    target = r.resolve(site, img.read(site, r.width), sec.addend(r))
                    bases[sym.secnum][(target - sym.value) & ((1 << (8 * r.width)) - 1)] += 1
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
                first = next((s for s in sec.syms if s.named), None)
                name = first.name if first else f"{o.name}:{sec.name}#{secnum}"
                yield ctx.fact(lo, hi, Kind.symbol, {"skind": "crt.data", "name": name, "extent": "proven", "unit": unit,
                                                     "section": sec.name, "bss": sec.data is None}, P)
                yield ctx.fact(lo, hi, Kind.unit, {"tu": unit, "lib": lib.name}, P)
                for s in sec.syms:
                    if s.named:
                        yield ctx.fact(lo + s.value, lo + s.value + 1, Kind.name, {"name": s.name, "origin": "lib", "unit": unit}, P)


@rule("S.thunk", version="2", ceiling=D, outputs=("symbol", "name"), needs=("S.imports", "S.crt.code"))
def thunk(ctx: RuleContext):
    """An import stub of the toolchain (Toolchain.import_stubs; VC6 / LINK: `FF 25 <slot>`, 6 bytes, `jmp dword
    ptr [slot]`) whose slot is an import address-table slot, in a code section, outside every placed library
    section, is a candidate. The same bytes are what the compiler emits for `return f(...)` when f is a
    dllimport function (VC6 does), as the last instruction of a function or as a whole function, so a
    candidate is an import thunk (named after the slot) only where the linker's layout makes it a library
    contribution (Toolchain.stub_placement; VC6 / LINK: library contributions follow the objects of the
    command line, the stubs of one import library are packed back to back): it lies at or after the start of
    the first placed library section, or another candidate lies one stub size (Toolchain.import_stub_size)
    before or after it while the stub size is below the function alignment (Toolchain.function_alignment;
    VC6: 16 bytes, so two compiled functions never lie a 6-byte stub apart). Every other candidate is
    compiled code, which the walk reaches."""
    img, tc = ctx.image, ctx.project.toolchain
    size = tc.import_stub_size
    packed = size < tc.function_alignment
    slots = {f.lo: f.value["name"] for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "iat"}
    crt = [(f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "func"]
    first_lib = min((a for a, _ in crt), default=None)
    cands = []
    for s in img.sections:
        if not s.holds_code:
            continue
        for p, slot in tc.import_stubs(img.section_data(s)):
            va = s.va + p
            if slot in slots and not any(a <= va < b for a, b in crt):
                cands.append((va, slots[slot]))
    at = {va for va, _ in cands}
    for va, name in cands:
        if (first_lib is not None and va >= first_lib) or packed and (va - size in at or va + size in at):
            yield ctx.fact(va, va + size, Kind.symbol, {"skind": "thunk", "name": name, "extent": "proven"}, D)
            yield ctx.fact(va, va + 1, Kind.name, {"name": "thunk:" + name, "origin": "import"}, D)


@rule("S.entry.user", version="1", ceiling=D, outputs=("name",), needs=("S.crt.refs", "S.entry", "S.codewalk"))
def entry_user(ctx: RuleContext):
    """The user entry: when the CRT names a symbol the CRT start-up calls (through S.crt.refs), that name is the
    user's entry function, reported as its C spelling for the layout (Toolchain.user_entry_names; VC6:
    _DllMain@12 -> DllMain, _main -> main, _WinMain@16 -> WinMain, _wmain -> wmain, _wWinMain@16 ->
    wWinMain)."""
    user = ctx.project.toolchain.user_entry_names()
    for f in ctx.facts(Kind.name):
        if f.value.get("origin") == "lib" and f.value["name"] in user:
            yield ctx.fact(f.lo, f.lo + 1, Kind.name, {"name": user[f.value["name"]], "origin": "entry"}, D)


@rule("S.strings", version="3", ceiling=D, outputs=("symbol",), needs=("S.relocs", "S.sections", "S.crt.data", "S.lib.data"))
def strings(ctx: RuleContext):
    """A relocation target in a data section whose bytes are at least 4 printable ASCII characters (0x20..0x7e,
    tab, CR, LF) followed by NUL is a string literal: the start is where the pointer points (proven), the extent
    runs to the first NUL (convention: C strings are NUL-terminated). A target inside an already claimed
    string is an inner reference, not a new string; bytes a placed library data section owns are that
    section's (its strings are named there)."""
    img = ctx.image
    data_secs = [s for s in img.sections if not s.holds_code]
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
        if not s.holds_code:
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
        sk = "unknown.code" if s.holds_code else "unknown.data"
        for a, b in claimed:
            if a > pos:
                yield ctx.fact(pos, a, Kind.symbol, {"skind": sk, "extent": "open"}, O)
            pos = max(pos, b)
        if s.end > pos:
            yield ctx.fact(pos, s.end, Kind.symbol, {"skind": sk, "extent": "open"}, O)
