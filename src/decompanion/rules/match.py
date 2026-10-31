"""Match rules (M.*): what the compiled objects say about the original.

  M.compile   one `build` fact per translation unit of the target (the tu table of the last `dcp build`): ok,
              object, diagnostics; a failed or never compiled unit is a gate error; the object-vs-source
              cross-check (M.gen)
  M.match     R1 [proven]: a function whose bytes equal the original's with the relocated fields masked (plus
              the DLL aid and the tail check, match/compare.py) owns [address, address + size)
  M.draft     R2 [derived, at most declared]: a compiled function that differs owns its code walk
  M8.reloc    M8 / M9 / M10: what our relocations refer to against what the original's sites hold

The sources remain the state: the `source` facts of L.src (an address comment, declared) are candidates the
match rules verify; a verified one yields facts above the declared level. Objects come from the store's tu
table (input `objects`); the rules never compile (`dcp build` does).
"""
from __future__ import annotations

from ..build import compile as build_compile
from ..ledger.fact import Kind, Level, Severity
from ..match import compare as C
from .engine import RuleContext, rule

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open

WALK = ("S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry")


# ------------------------------------------------------------------------------------------------ M.compile
@rule("M.compile", version="2", ceiling=P, outputs=("build",), inputs=("objects", "src", "decl", "targets", "config", "toolchain"),
      needs=("S.sections",), helpers=(build_compile.plan, build_compile.flags_for, build_compile.compile_flags,
                                      build_compile.unit_overrides))
def compile_facts(ctx: RuleContext):
    """One `build` fact per translation unit of the current target (build/tu.py: a unit with at least one
    function of the target), at its least function address (the image base when it has none): tu, ok, the
    object's hash, the flags, its errors (the compiler's diagnostics, file and line in the unit's file) and its
    warning count, and `stale` when the unit's text or flags changed since the compile the tu table records.
    Gate errors (check M.compile): a unit that failed to compile (the first errors), a unit never compiled
    (a warning when the toolchain is not installed: nothing can be compiled on this machine); a stale unit is a
    warning (`dcp build` compiles it; `dcp check` builds first). An override table
    ([[toolchain.unit]]) without a reason is an error. M.gen, the object-vs-source cross-check (the first
    attempt's gen.py): every function the unit's object defines has an address comment of the target (or
    `unlinked`) in the unit, and every such function is defined by the object; either side alone is an error."""
    p, img = ctx.project, ctx.image
    tus = ctx.input("objects")
    for o in build_compile.unit_overrides(p):
        if not str(o.get("reason", "")).strip():
            yield ctx.conflict(Severity.error, "M.compile", img.base, img.base + 1,
                               f"[[toolchain.unit]] glob={o.get('glob')!r}: an override without a reason")
    tc = p.toolchain
    for a in build_compile.plan(p):
        at = a.first_addr if a.first_addr is not None and img.in_image(a.first_addr) else img.base
        row = tus.get(a.unit)
        flags = build_compile.compile_flags(p, a.target, a.unit)
        if row is None:
            yield ctx.fact(at, at + 1, Kind.build, {"tu": a.unit, "ok": False, "stale": True, "errors": ["not compiled"],
                                                    "warnings": 0, "functions": len(a.functions)}, P)
            if tc.available():
                yield ctx.conflict(Severity.error, "M.compile", at, at + 1, f"unit {a.unit} is not compiled (dcp build)")
            else:
                yield ctx.conflict(Severity.warn, "M.compile", at, at + 1,
                                   f"unit {a.unit} is not compiled: the toolchain is not available (root {tc.root})")
            continue
        errors = [f"{f}({l}): {sev} {code}: {msg}" if f else f"{sev} {code}: {msg}" for f, l, sev, code, msg in row["diags"] if sev == "error"]
        warnings = sum(1 for d in row["diags"] if d[2] == "warning")
        stale = row["src_hash"] != a.src_hash or row["flags"] != flags
        v = {"tu": a.unit, "ok": row["ok"], "stale": stale, "flags": " ".join(row["flags"]), "warnings": warnings,
             "functions": len(a.functions), "file": a.file}
        if row["ok"]:
            v["obj"] = row["obj_hash"][:16]
        if errors:
            v["errors"] = errors[:20]
        yield ctx.fact(at, at + 1, Kind.build, v, P)
        if not row["ok"]:
            last = (row["log"].strip().splitlines() or ["no diagnostics"])[-1]
            yield ctx.conflict(Severity.error, "M.compile", at, at + 1, f"unit {a.unit} does not compile: " + ("; ".join(errors[:3]) or last))
        elif stale:
            yield ctx.conflict(Severity.warn, "M.compile", at, at + 1, f"unit {a.unit} changed since its compile (dcp build)")
        if not row["ok"]:
            continue
        obj = C.read_object(p, row["obj_hash"])
        if obj is None:
            continue
        defined = {}
        for s in obj.functions():
            defined.setdefault(tc.undecorate(s.name), s)
        ours = {}
        for addr, name in a.functions:
            ours.setdefault(name, addr)
        for name in sorted(set(defined) - set(ours)):
            yield ctx.conflict(Severity.error, "M.gen", at, at + 1,
                               f"unit {a.unit}: the object defines {name} ({defined[name].name}), no address comment of "
                               f"the target in {a.file} does")
        for name, addr in sorted(ours.items()):
            where = addr if addr is not None and img.in_image(addr) else at
            if name not in defined:
                yield ctx.conflict(Severity.error, "M.gen", where, where + 1,
                                   f"{a.file}: the object of unit {a.unit} defines no function {name} (dropped by the "
                                   f"compiler as an unreferenced static, or not parsed as a definition)")


# ------------------------------------------------------------------------------------------------ M.match / M.draft
@rule("M.match", version="1", ceiling=P, outputs=("symbol", "source"), needs=("L.src", *WALK), inputs=("objects",), native=True)
def match(ctx: RuleContext):
    """R1. A sourced function of the current target (an L.src `source` fact: a candidate, its declared level
    does not propagate) whose unit's object defines its function is a byte match when (match/compare.py):
    every byte of the function's section (from its symbol to the next named symbol or the section end) equals
    the image's byte at the source's address, relocated fields masked; the original does not continue after
    our last byte (the bytes up to the next known start are toolchain fill, or none); and, when the image
    carries base relocations (a dll: the complete list of its absolute fields), every absolute relocation site
    of ours is a base-relocation site and the extent holds as many base relocations as we have absolute
    relocations (`relocs 7/7`). A match owns its bytes: a `symbol` func proven (value: name, unit, file,
    relocs) from its address to the end of its last instruction that is no alignment fill (CL pads a function's
    section with fill up to the next function's alignment: the fill keeps its own symbol), or to the first jump
    or index table the walk found for it inside the section (VC6 places a switch's tables in the function's
    section; the tables keep their own symbols); and a `source` fact (what: match) over the whole section,
    proven. Native: native/dcp_core/src/rules.rs m_match."""
    return ()


@rule("M.draft", version="1", ceiling=D, outputs=("source",), needs=("L.src", *WALK), inputs=("objects",), native=True)
def draft(ctx: RuleContext):
    """R2. A sourced function of the current target whose compiled function is no byte match (M.match's
    criterion fails) owns the bytes the code walk gives its start: a `source` fact (what: draft) over the walk's
    function extent (S.codewalk, derived), with why it is no match (differing bytes, the original continuing,
    the relocation aid). Its level is the lower of the walk's and the address comment's (declared). A function
    whose start the walk does not know owns nothing. Native: native/dcp_core/src/rules.rs m_draft."""
    return ()


# ------------------------------------------------------------------------------------------------ M8 / M9 / M10
@rule("M8.reloc", version="2", ceiling=P, needs=("L.src", *WALK, "kind:name"), inputs=("objects",), native=True)
def reloc_checks(ctx: RuleContext):
    """For every compiled function that is a byte match, or whose bytes differ while the DLL aid holds (every
    absolute site of ours is a base-relocation site and the counts agree), each absolute or relative
    relocation of ours whose site lines up with the original's code (rules.rs aligned_sites: the same
    instruction at the same offset, equal outside our relocated fields; the aid alone says nothing about
    relative sites, and a function without absolute sites passes it trivially) is resolved against the image
    (the address the original's site refers to, Reloc.resolve with our addend). A site that does not line up
    says nothing: the difference is the function's draft diff (M.draft), not a contradiction.
    M8: the symbol we reference has a registered address (a name fact: export, import slot, library, source,
    declaration) and the original's site refers to another address: our object references X where the original
    holds the address registered to Y (severity from the two levels).
    M9: we reference a string literal and the original's bytes at the resolved address differ from our
    literal's bytes (text or terminator).
    M10: we reference a floating constant and the original's bytes there differ from its bits. Native:
    native/dcp_core/src/rules.rs m8_reloc."""
    return ()


# ------------------------------------------------------------------------------------------------ M.flags.proven
from ..build import probe as probe_mod  # noqa: E402


@rule("M.flags.proven", version="1", ceiling=P, outputs=("toolchain",), inputs=("probe", "toolchain"),
      helpers=(probe_mod.analyse,))
def flags_proven(ctx: RuleContext):
    """From the last `dcp toolchain probe` (build/probe.py): one `toolchain` fact per flag group of the probe
    grid, over the image, naming the best combination's flag, the user anchors that distinguish it (they match
    under it and stop matching when only that group takes another value) and their units. Proven when the
    distinguishing anchors come from at least two units; else declared (the target's declaration stays what
    says it). A proven flag the target's declared cflags do not contain is an error (M.flags)."""
    res = ctx.input("probe")
    if not res:
        return
    img = ctx.image
    an = probe_mod.analyse(res)
    declared = {f.lower() for f in (ctx.input("toolchain").get("cflags") or [])}
    for g in an["groups"]:
        lvl = P if len(g["units"]) >= 2 else DE
        yield ctx.fact(img.base, img.end, Kind.toolchain, {"flag": g["flag"], "group": g["group"], "anchors": len(g["anchors"]),
                                                          "units": len(g["units"]), "crt_anchors": len(g["crt_anchors"])}, lvl)
        if lvl == P and g["flag"].lower() not in declared:
            yield ctx.conflict(Severity.error, "M.flags", img.base, img.base + 1,
                               f"the probe proves {g['flag']} ({g['group']}, {len(g['anchors'])} anchors from {len(g['units'])} units); "
                               f"the declared cflags do not hold it")


# ------------------------------------------------------------------------------------------------ M5 / M6 / M7


def lint_units(p) -> dict:
    """What M.lint reads that only Python computes: {units: unit -> its text's hash today} (build_compile.plan)."""
    return {"units": {a.unit: a.src_hash for a in build_compile.plan(p)}}


@rule("M.lint", version="2", ceiling=P, needs=("L.src",), inputs=("lint", "src"), helpers=(build_compile.plan,),
      native=True, native_inputs=lint_units)
def lint_checks(ctx: RuleContext):
    """The last `dcp lint` (source/lint.py: clang as a C89 type checker with MS compatibility against the
    toolchain's headers; `@original why` / `@vc6 why` on a line exempt it): M6 an error inside one unit, M5 a
    declaration conflict across units (the all-declarations unit), both errors; M7 a call through a K&R
    declaration or without a declaration, a warning (readability rule Q7 counts it). Reported at the address
    of the function whose span holds the diagnostic's line (the image base when none does). A lint run whose units'
    texts differ from today's units is stale: a warning (`dcp lint`; `dcp check` lints first). Native:
    native/dcp_core/src/rules.rs m_lint."""
    return ()
