"""Data rules (M.data.*, D*): where the data objects of the sources lie (lifted in part from the first attempt's
ledger/ledger_data.py and ledger/evidence.py; evidence kinds site and content; iat / lib and D2 / D3 / D7 /
D8 are later work).

A data object of the sources is a definition (or an `extern`) with an address comment (srcscan): the L.src
`source` facts (what: data) and `name` facts are its candidates. Its size and section kind come from the
object of its unit (ObjectFormat data_symbols: data / rdata / bss / common).

  M.data.site     [proven]   a byte-matched function's relocation refers to the data symbol and the original's
                             site holds exactly the declared address
  M.data.content  [proven]   the object's initialised bytes of the symbol (relocated fields masked) equal the
                             image's at the declared address and occur at no other address of the image's
                             initialised data
  M.data.draft    [declared] every other data definition with an address: it owns its declared extent
  D.data          D1 the declared extent overlaps the next symbol; D4 the definitions of one unit and section
                  kind are not in address order; D5 a tentative definition (common) declared in the original's
                  uninitialised data (it needs `= 0` to be placed with its unit); D6 a pointer-table entry of
                  ours refers to another address than the original's entry
"""
from __future__ import annotations

import bisect

from ..ledger.fact import Kind, Level, Severity, severity_of
from ..match import compare as C
from ..objfmt.base import ABSOLUTE
from .engine import RuleContext, rule
from .match import WALK, compiled_functions, name_registry, starts_of

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open


def data_objects(ctx):
    """[(source fact, unit object or None, data symbol or None, kind, size)] of every data definition of the
    current target with an address (L.src source facts, what: data), the symbol looked up by its C name in the
    object of its unit."""
    p, tc = ctx.project, ctx.project.toolchain
    objs = C.objects(p, ctx.input("objects"))
    index = {}
    for u, o in objs.items():
        idx = {}
        for s, kind, size in o.data_symbols():
            idx.setdefault(tc.undecorate(s.name), (s, kind, size))
        index[u] = (o, idx)
    out = []
    for f in sorted(ctx.facts(Kind.source), key=lambda f: (f.lo, f.value["file"])):
        if f.run != "L.src" or f.value.get("what") != "data":
            continue
        o, idx = index.get(f.value["unit"], (None, {}))
        hit = idx.get(f.value["symbol"])
        out.append((f, o, hit[0] if hit else None, hit[1] if hit else None, hit[2] if hit else None))
    return out


def site_confirmed(ctx) -> dict[int, str]:
    """address -> C name of every data address a byte-matched function's relocation confirms (M.data.site)."""
    img, tc = ctx.image, ctx.project.toolchain
    funcs, _ = compiled_functions(ctx)
    out = {}
    for s, obj, sym, code, c in funcs:
        if not c.matched:
            continue
        for off, r, target in code.relocs:
            if target is None or not target.named or target.function or target.constant or target.dllimport or r.kind != ABSOLUTE:
                continue
            site = s.lo + off
            to = r.resolve(site, img.read(site, r.width), code.section.addend(r))
            if to is not None:
                out.setdefault(to, tc.undecorate(target.name))
    return out


def masked_equal(img, at, data: bytes, mask: bytes) -> bool:
    have = img.read(at, len(data))
    return all(mask[k] or data[k] == have[k] for k in range(len(data)))


def content_hits(img, data: bytes, mask: bytes, limit: int = 2) -> list[int]:
    """Addresses of the image's initialised non-code data where data occurs (masked), at most `limit`."""
    k0 = 0
    run = b""
    i = 0
    while i < len(data):                       # the longest unmasked run anchors the search
        if mask[i]:
            i += 1
            continue
        j = i
        while j < len(data) and not mask[j]:
            j += 1
        if j - i > len(run):
            run, k0 = data[i:j], i
        i = j
    if len(run) < 4:
        return []
    out = []
    for s in img.sections:
        if s.holds_code or s.uninitialized:
            continue
        raw = img.section_data(s)
        p = raw.find(run)
        while p >= 0:
            at = s.va + p - k0
            if at >= s.va and masked_equal(img, at, data, mask):
                out.append(at)
                if len(out) >= limit:
                    return out
            p = raw.find(run, p + 1)
    return out


def symbol_bytes(sym, size):
    """(bytes, mask) of a data symbol of an initialised section."""
    sec = sym.section
    if sec is None or sec.data is None:
        return None, None
    m = sec.mask()
    return bytes(sec.data[sym.value:sym.value + size]), bytes(m[sym.value:sym.value + size])


def extent(f, size):
    return f.lo, f.lo + max(1, size or 1)


@rule("M.data.site", version="1", ceiling=P, outputs=("symbol",), needs=("L.src", *WALK, "M.match"), inputs=("objects",),
      helpers=(data_objects, site_confirmed, compiled_functions, starts_of, extent, C))
def data_site(ctx: RuleContext):
    """A data definition with an address comment whose address a byte-matched function's absolute relocation
    to the same symbol confirms (the original's site holds exactly that address, Reloc.resolve with our
    addend) is placed: a `global` symbol proven over [address, address + the object's size of the symbol)
    {name, unit, extent: site}."""
    confirmed = site_confirmed(ctx)
    for f, o, sym, kind, size in data_objects(ctx):
        if confirmed.get(f.lo) == f.value["symbol"]:
            lo, hi = extent(f, size)
            yield ctx.fact(lo, hi, Kind.symbol, {"skind": "global", "name": f.value["symbol"], "unit": f.value["unit"],
                                                "extent": "site", "kind": kind or "-"}, P)


@rule("M.data.content", version="1", ceiling=P, outputs=("symbol",), needs=("L.src", *WALK, "M.match"), inputs=("objects",),
      helpers=(data_objects, site_confirmed, compiled_functions, starts_of, content_hits, masked_equal, symbol_bytes, extent, C))
def data_content(ctx: RuleContext):
    """A data definition with an address comment that M.data.site does not place, defined in an initialised
    section of its object with at least 4 bytes that are no relocated field and not all zero, whose bytes
    (relocated fields masked) equal the image's at the declared address and occur at no other address of the
    image's initialised data sections: a `global` symbol proven {extent: content}. Found elsewhere only once
    and not at the declared address: an error (M.data.content): the declaration names another object's place."""
    img = ctx.image
    confirmed = site_confirmed(ctx)
    for f, o, sym, kind, size in data_objects(ctx):
        if sym is None or kind not in ("data", "rdata") or confirmed.get(f.lo) == f.value["symbol"]:
            continue
        data, mask = symbol_bytes(sym, size)
        if data is None or sum(1 for k in range(len(data)) if not mask[k]) < 4 or not any(
                data[k] for k in range(len(data)) if not mask[k]):
            continue
        hits = content_hits(img, data, mask)
        if hits == [f.lo]:
            lo, hi = extent(f, size)
            yield ctx.fact(lo, hi, Kind.symbol, {"skind": "global", "name": f.value["symbol"], "unit": f.value["unit"],
                                                "extent": "content", "kind": kind}, P)
        elif len(hits) == 1 and not masked_equal(img, f.lo, data, mask):
            yield ctx.conflict(Severity.error, "M.data.content", f.lo, f.lo + 1,
                               f"{f.value['symbol']}: its bytes occur once in the image, at {hits[0]:#x}, not at the declared {f.lo:#x}",
                               a=f.by)


@rule("M.data.draft", version="1", ceiling=DE, outputs=("symbol",), needs=("L.src", "M.data.site", "M.data.content"),
      inputs=("objects",), helpers=(data_objects, extent, C))
def data_draft(ctx: RuleContext):
    """Every data definition with an address comment that neither M.data.site nor M.data.content places owns
    its declared extent: a `global` symbol, declared, over [address, address + the object's size) (one byte
    when its unit has no object or the object lacks the symbol) {extent: draft}."""
    placed = {f.lo for f in ctx.facts(Kind.symbol)}
    for f, o, sym, kind, size in data_objects(ctx):
        if f.lo in placed:
            continue
        lo, hi = extent(f, size)
        yield ctx.fact(lo, hi, Kind.symbol, {"skind": "global", "name": f.value["symbol"], "unit": f.value["unit"],
                                            "extent": "draft", "kind": kind or "-"}, DE)


@rule("D.data", version="1", ceiling=P, needs=("L.src", "M.data.site", "M.data.content", "M.data.draft", "S.crt.data",
                                              "S.strings", "S.imports", "S.relocs", "S.sections", "kind:name"),
      inputs=("objects",), helpers=(data_objects, name_registry, C))
def data_checks(ctx: RuleContext):
    """D1: a data definition's extent [address, address + the object's size) holds the start of another
    symbol (a data symbol of the sources, a CRT data block, a string, an import slot). D4: in one unit, the
    definitions of one section kind (data / rdata / bss) are not in increasing address order in the order the
    amalgamation defines them (VC6 places a unit's definitions of a section in definition order). D5: a
    tentative definition (the object holds it as common: the linker allocates it apart from its unit) whose
    declared address lies in the image's uninitialised data (no file bytes): write it `= 0`. D6: an absolute
    relocation inside a definition of ours (a pointer-table entry) whose symbol has a registered address while
    the original's entry at the same offset holds another one."""
    img, tc = ctx.image, ctx.project.toolchain
    objs = data_objects(ctx)
    starts = sorted({f.lo for f in ctx.facts(Kind.symbol) if f.value.get("skind") in ("global", "crt.data", "string", "iat")}
                    | {f.lo for f, *_ in objs})
    for f, o, sym, kind, size in objs:
        if size and size > 1:
            i = bisect.bisect_right(starts, f.lo)
            if i < len(starts) and starts[i] < f.lo + size:
                yield ctx.conflict(Severity.error, "D1", f.lo, f.lo + size,
                                   f"{f.value['symbol']} at {f.lo:#x} ({size} bytes) overlaps the symbol at {starts[i]:#x}", a=f.by)
        if sym is not None and sym.common:
            sec = img.section_of(f.lo)
            if sec is not None and img.off(f.lo) is None:
                yield ctx.conflict(Severity.error, "D5", f.lo, f.lo + 1,
                                   f"{f.value['symbol']} at {f.lo:#x} lies in uninitialised data and is a tentative definition: "
                                   f"write it `= 0` so it is placed with its unit", a=f.by)
    # D4: per unit and section kind, in amalgamation order (file order: head.c first, then the fragments by address)
    per = {}
    for f, o, sym, kind, size in objs:
        if kind in ("data", "rdata", "bss"):
            per.setdefault((f.value["unit"], kind), []).append(f)
    for (unit, kind), fs in sorted(per.items()):
        order = sorted(fs, key=lambda f: (0 if f.value["file"].endswith("/head.c") else 2 if f.value["file"].endswith("/tail.c") else 1,
                                          f.value["file"], f.value["line"]))
        for a, b in zip(order, order[1:]):
            if b.lo < a.lo:
                yield ctx.conflict(Severity.error, "D4", b.lo, b.lo + 1,
                                   f"unit {unit} ({kind}): {b.value['symbol']} ({b.lo:#x}) is defined after {a.value['symbol']} "
                                   f"({a.lo:#x}) but lies before it", a=b.by, b=a.by)
    by_name, by_addr = name_registry(ctx)
    for f, o, sym, kind, size in objs:
        if sym is None or sym.section is None or sym.section.data is None or not size:
            continue
        for r in sym.section.relocs:
            if not (sym.value <= r.offset < sym.value + size) or r.kind != ABSOLUTE:
                continue
            target = o.symbols.get(r.symbol_index)
            if target is None or not target.named or target.constant:
                continue
            site = f.lo + r.offset - sym.value
            to = r.resolve(site, img.read(site, r.width), sym.section.addend(r))
            cname = tc.undecorate(target.imported if target.dllimport else target.name)
            regs = by_name.get(cname)
            if not regs or to in regs:
                continue
            (b, lvl), = sorted(regs.items())[:1]
            yield ctx.conflict(severity_of(P, lvl), "D6", site, site + r.width,
                               f"{f.value['symbol']} +{r.offset - sym.value:#x}: our entry refers to {cname} (registered at {b:#x}), "
                               f"the original's to {to:#x} ({', '.join(sorted(by_addr.get(to, ()))) or 'nothing registered'})", a=f.by)
