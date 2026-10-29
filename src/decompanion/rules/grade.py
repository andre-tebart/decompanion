"""Grades (G.*): two grades per (function, target), computed, nothing typed by hand (lifted from the first
attempt's ledger/grade.py; "behaviour" is called "shape" here: a diff explained by register, slot and
scheduling classes proves the same shape, not the same behaviour).

  code          draft -> shape -> byte       what our compiled function is against the original's bytes
  readability   draft -> readable            whether a reader can follow the C without the disassembly

Code rules:
  B1 byte    M.match holds for the function (masked bytes equal, the original ends where we end, the DLL aid).
  B2 shape   the bytes differ, but every differing hunk of the instruction diff (match/diffclass.py) is `fill`,
             `order`, or explained by the ISA (`regs`, `slots`, `order` after a register renaming, `sib`,
             `fpu`); or the instructions left in the `code` hunks are the same multiset on both sides; or the
             whole function is equal under one bijective renaming of registers and stack slots. Identical
             instruction text (a byte difference in a relocated field only) is shape too. Not a proof of equal
             behaviour: what the instruction diff can see.
  B3 draft   a `code` hunk B2 does not explain remains, or the function has no compiled object to compare.
Readability rules, on the fragment's text (comments and strings blanked for the code tests):
  Q1 name         the function's own name is no placeholder (`Unk` + 4 hex digits, or ending in 6 hex digits with
                  a digit among them: FUN_10008d20, Unk10008d20, thread_10008d20).
  Q2 identifiers  no placeholder identifier in the definition: the Q1 forms, `param_N`, `xVarN`, `local_N`,
                  `DAT_` / `PTR_` / `FUN_` / `LAB_` names, `unk` / `unk_` + hex.
  Q3 addresses    no integer literal inside the image's address range in the code.
  Q4 raw access   no `*(T *)` dereference-cast, and no use of a macro any source or header defines with one.
  Q5 markers      no draft marker in the address comment or the body: ROUGH, SKELETON, TODO, FIXME, XXX
                  (whole words) or the `@rough` tag.
  Q6 described    the address comment carries text after the address, or another comment of any source or
                  header starts with the function's address and carries text after it.
  Q7 prototypes   every call goes through a prototype (clang lint, `dcp lint`): evaluated only when a lint run
                  is recorded for the target (input `lint`); without one Q7 is not evaluated and says so.
  Q8 complete     our compiled code is at least half the original's code size (the walk's or the source
                  extent's): a stub (`void f(void) {}`) or an unfinished body cannot be followed as the original,
                  however good its names (without it a named, described stub graded readable).
Unit grades: code = the lowest code grade of its functions; readable only when every function is readable
and the unit's name has an origin other than `guess` (its start boundary's `by=`).
"""
from __future__ import annotations

import functools
import json
import re

from .. import fsmemo
from ..build import compile as build_compile
from ..ledger import srcscan
from ..ledger.fact import Kind, Level, Severity
from ..ledger.store import sha256
from ..match import diffclass as DC
from .engine import RuleContext, rule
from .match import WALK, compiled_functions, starts_of
from ..match import compare as C

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open
CODE = ("draft", "shape", "byte")
READ = ("draft", "readable")
CODE_RANK = {c: i for i, c in enumerate(CODE)}

PLACEHOLDER = re.compile(r"Unk[0-9a-fA-F]{4,}|^(?=.*\d)[A-Za-z_]\w*?[0-9a-fA-F]{6}$|^param_\d+$|^[a-z]{1,3}Var\d+$|^local_[0-9a-f]+$"
                         r"|^_?(?:DAT|PTR|FUN|LAB)_[0-9a-fA-F]+$|^unk_?[0-9a-fA-F]{1,8}$")
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
LITERAL = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)[uUlL]*(?![\w.])")
DEREF_CAST = re.compile(r"\*\s*\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*"
                        r"(?:\s+[A-Za-z_]\w*)*\s*\*+\s*(?:const\s*)?\)")
READABILITY_VERSION = "1"                          # bump when readability() changes its verdicts
DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(([^)]*)\)[ \t]*((?:\\\n|[^\n])*)", re.M)
MARKER = re.compile(r"\b(ROUGH|SKELETON|TODO|FIXME|XXX)\b")
DESCRIBED = re.compile(r"\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?(0x[0-9a-fA-F]+)\b\s*(.*)", re.S)


def brace_end(code: str, k: int) -> int:
    """The index after the brace that closes the one at k."""
    depth = 0
    for i in range(k, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(code)


@functools.lru_cache(maxsize=8)
def context(root: str, tree: str) -> tuple[frozenset, frozenset]:
    """(raw macro names (Q4), described addresses (Q6)) over every source and header of the tree (collected by
    the source scan, per file)."""
    sc = srcscan.scan(root, tree)
    defs = {}
    for name, body in sc.macros:
        defs.setdefault(name, body)
    described = set(sc.described)
    raw = {n for n, body in defs.items() if DEREF_CAST.search(body)}
    while raw:
        pat = re.compile(r"\b(" + "|".join(sorted(map(re.escape, raw))) + r")\s*\(")
        more = {n for n, body in defs.items() if n not in raw and pat.search(body)}
        if not more:
            break
        raw |= more
    return frozenset(raw), frozenset(described)


def readability(root, tree: str, fn_value: dict, addr: int, image_range, lint=None) -> tuple[str, list[str]]:
    """(readable | draft, [failing rule with evidence]) of one function fragment (Q1..Q7, module docstring)."""
    from pathlib import Path
    rel, name = fn_value["file"], fn_value["symbol"]
    p = Path(root) / rel
    if not p.exists():
        return "draft", ["the fragment is gone"]
    S = srcscan.Source(rel, fsmemo.read_text(p))
    defs = [d for d in S.definitions() if d[1] == name]
    if not defs:
        return "draft", ["definition not found by the parser"]
    off = defs[-1][0]
    k = S.code.find("{", off)
    end = brace_end(S.code, k) if k >= 0 else len(S.code)
    code = S.code[off:end]
    raw, described = context(str(root), tree)
    fails = []
    if PLACEHOLDER.search(name):
        fails.append(f"Q1 name: {name} is a placeholder")
    words = IDENT.findall(code)
    idents = sorted({w for w in words if w != name and PLACEHOLDER.search(w)})
    if idents:
        fails.append("Q2 identifiers: " + ", ".join(idents[:8]) + (f" (+{len(idents) - 8} more)" if len(idents) > 8 else ""))
    lo, hi = image_range
    lits = []
    for m in LITERAL.finditer(code):
        s = m.group(1)
        try:
            v = int(s, 16) if s[:2] in ("0x", "0X") else int(s, 8) if len(s) > 1 and s[0] == "0" else int(s, 10)
        except ValueError:
            continue
        if lo <= v < hi and s not in lits:
            lits.append(s)
    if lits:
        fails.append("Q3 addresses: " + ", ".join(lits[:6]))
    casts = DEREF_CAST.findall(code)
    macros = sorted({w for w in words if w in raw})
    if casts or macros:
        fails.append("Q4 raw access: " + ", ".join(([f"{len(casts)} x `*(T *)`"] if casts else []) + ["macro " + m for m in macros]))
    first = S.comments[0][2] if S.comments else ""
    texts = [first] + [b for s, e, b in S.comments if off <= s < end] + [code]
    marks = sorted({m.group(1) for t in texts for m in MARKER.finditer(t)})
    if fn_value.get("rough"):
        marks.append("@rough")
    if marks:
        fails.append("Q5 markers: " + ", ".join(marks))
    if addr not in described:
        fails.append("Q6 described: no text after the address, no other comment describes it")
    if lint is not None:
        bad = lint.get(rel)
        if bad:
            fails.append("Q7 prototypes: " + ", ".join(bad[:6]))
    return ("draft" if fails else "readable"), fails


_ctx_digest: dict[str, str] = {}


def readability_cached(store, root, tree, fn_value, addr, image_range, lint=None):
    """readability(), memoised in the store by everything it reads: the fragment's text, the function's tags,
    its address, the tree's context (macros, described addresses) and its lint entry."""
    from pathlib import Path
    p = Path(root) / fn_value["file"]
    if not p.exists():
        return readability(root, tree, fn_value, addr, image_range, lint)
    dig = _ctx_digest.get(tree)
    if dig is None:
        raw, described = context(str(root), tree)
        dig = _ctx_digest[tree] = sha256(json.dumps(sorted(raw)), json.dumps(sorted(described)))
    key = sha256("readability", READABILITY_VERSION, fsmemo.sha256(p), json.dumps(fn_value, sort_keys=True), f"{addr:x}",
                 dig, json.dumps(list(image_range)), json.dumps(lint.get(fn_value["file"]) if lint is not None else None))
    hit = store.blob_json(key)
    if hit is not None:
        return hit[0], hit[1]
    q, qf = readability(root, tree, fn_value, addr, image_range, lint)
    store.put_blob_json(key, "readability", [q, qf])
    return q, qf


@rule("G.grade", version="3", ceiling=P, outputs=("grade",), needs=("L.src", "M.match", "L.unit.extent", "L.src.extent", *WALK),
      inputs=("objects", "src", "lint"), helpers=(compiled_functions, starts_of, readability, readability_cached, context, brace_end, DC, C,
                                                         build_compile.plan))
def grade(ctx: RuleContext):
    """The grades of every function fragment of the current target and of every unit (the rules B1..B3, Q1..Q8
    and the unit grades of rules/grade.py's module docstring), as `grade` facts: a function's at its address
    {of: function, name, unit, file, code, readability, level (deep / stuck from the address comment's tag, ''
    for base), failing (the failing rules with evidence), dist (differing instructions, differing bytes, our
    size, the original's code size: a report, not a gate), hunks}; a unit's over its extent {of: unit, code,
    readability, functions, named_by}. A function's grade fact is proven when its code is byte (M.match), else
    declared (its address comment is the premise). Q7 is evaluated only for the units whose amalgamation the
    last `dcp lint` parsed (the store meta `lint`)."""
    p, img, tc = ctx.project, ctx.image, ctx.project.toolchain
    funcs, missing = compiled_functions(ctx)
    matched = {f.lo for f in ctx.facts(Kind.symbol) if f.run == "M.match"}
    walk = {f.lo: f for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "func" and f.run in ("S.codewalk", "L.src.extent")}
    lint = ctx.input("lint")
    lint_calls = lint.get("calls") if lint else None
    # Q7 only for units whose text is what the last lint parsed
    current = {a.unit: a.src_hash for a in build_compile.plan(p)} if lint else {}
    linted = {u for u, h in (lint or {}).get("units", {}).items() if current.get(u) == h}
    tree = p.input_hash("src")
    plug = p.input_hash("plugins")
    rng = (img.base, img.end)
    rows = []
    for s, obj, sym, code, c in funcs:
        w = walk.get(s.lo)
        skey = sha256("codesize", DC.VERSION, plug, code.data.hex(), code.mask.hex(), f"{s.lo:x}")
        size = ctx.store.blob_json(skey)
        if size is None:
            size = DC.code_size(p.isa, img, code.data, code.mask, s.lo, tc.fill_forms)
            ctx.store.put_blob_json(skey, "codesize", size)
        orig_size = (w.hi - s.lo) if w is not None else size
        n = min(size, orig_size)
        nbytes = sum(1 for k in c.diffs if k < n) + abs(size - orig_size)
        if s.lo in matched:
            g, why, hunks, dist_ins = "byte", [], {}, 0
        else:
            key = sha256("diffclass", DC.VERSION, plug, code.data.hex(), code.mask.hex(), f"{s.lo:x}", img.read(s.lo, orig_size).hex())
            cached = ctx.store.blob_json(key)
            if cached is None:
                A, B = DC.listings(p.isa, img, code.data, code.mask, s.lo, orig_size, tc.fill_forms)
                v = DC.verdict(A, B, p.isa)
                ctx.store.put_blob_json(key, "diffclass", v.to_json())
            else:
                v = DC.Verdict.from_json(cached)
            g = "shape" if v.shape else "draft"
            hunks, dist_ins = v.hunks, v.distance
            why = [f"B1 byte: {c.why()}"] if c.why() else []
            if g == "draft":
                why.append("B3 draft: unexplained code hunks: " + v.summary())
            else:
                why.append("B2 shape: " + v.summary())
        rows.append((s, g, why, hunks, {"ins": dist_ins, "bytes": nbytes, "size": size, "orig": orig_size}))
    for s, reason in missing:
        w = walk.get(s.lo)
        rows.append((s, "draft", [f"B3 draft: {reason}"], {}, {"ins": None, "bytes": None, "size": None,
                                                               "orig": (w.hi - s.lo) if w is not None else None}))
    per_unit = {}
    for s, g, why, hunks, dist in sorted(rows, key=lambda r: r[0].lo):
        q, qf = readability_cached(ctx.store, p.root, tree, s.value, s.lo, rng, lint_calls if s.value["unit"] in linted else None)
        if dist.get("size") and dist.get("orig") and dist["size"] * 2 < dist["orig"]:     # Q8: a stub is not readable
            q, qf = "draft", qf + [f"Q8 complete: our code is {dist['size']} bytes, the original's {dist['orig']}: the body is "
                                    f"a stub or unfinished (at least half the original's size)"]
        level = "stuck" if s.value.get("stuck") is not None else ("deep" if s.value.get("deep") is not None else "")
        v = {"of": "function", "name": s.value["symbol"], "unit": s.value["unit"], "file": s.value["file"], "code": g,
             "readability": q, "level": level, "failing": why + qf, "dist": dist}
        if hunks:
            v["hunks"] = hunks
        if s.value.get("deep") is not None and s.value.get("stuck") is not None:
            yield ctx.conflict(Severity.error, "M2", s.lo, s.lo + 1, f"{s.value['symbol']}: carries both @deep and @stuck", a=s.by)
        elif level and g == "byte" and q == "readable":
            yield ctx.conflict(Severity.warn, "M2", s.lo, s.lo + 1, f"{s.value['symbol']}: byte + readable, its @{level} tag is stale "
                                                                    f"(dcp build clears it)", a=s.by)
        yield ctx.fact(s.lo, s.lo + 1, Kind.grade, v, P if g == "byte" else DE)
        per_unit.setdefault(s.value["unit"], []).append(v)
    for u in ctx.facts(Kind.unit):
        if "status" not in u.value:
            continue
        fs = per_unit.get(u.value["tu"])
        if not fs:
            continue
        code = min((f["code"] for f in fs), key=CODE_RANK.get)
        named = u.value.get("named_by")
        readable = all(f["readability"] == "readable" for f in fs) and named not in (None, "guess")
        yield ctx.fact(u.lo, u.hi, Kind.grade, {"of": "unit", "unit": u.value["tu"], "code": code,
                                               "readability": "readable" if readable else "draft", "functions": len(fs),
                                               "named_by": named or "-"}, min(u.level, DE))


# ------------------------------------------------------------------------------------------------ M1
def parse_baseline(text: str) -> dict[tuple[str, int], dict]:
    """(target, address) -> {name, unit, code, readability, level} of a ledger/grades.tsv text (a header line
    and one tab-separated line per function: target, address, name, unit, code, readability, level)."""
    out = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith(("#", "target\t")):
            continue
        f = line.split("\t")
        f += [""] * (7 - len(f))
        try:
            a = int(f[1], 16)
        except ValueError:
            continue
        out[(f[0], a)] = {"name": f[2], "unit": f[3], "code": f[4], "readability": f[5], "level": f[6]}
    return out


def falls(base: dict, now: dict | None) -> list[str]:
    """What fell from a baseline row to the current grade (None: the function has no grade any more)."""
    if now is None:
        return [f"graded {base['code']} + {base['readability']} in the baseline, no grade now (its fragment is gone?)"]
    out = []
    if base["code"] in CODE_RANK and CODE_RANK[now["code"]] < CODE_RANK[base["code"]]:
        out.append(f"code {base['code']} -> {now['code']}")
    if base["readability"] == "readable" and now["readability"] != "readable":
        out.append("readability readable -> draft")
    return out


@rule("M1.baseline", version="1", ceiling=P, needs=("G.grade",), inputs=("baseline",), helpers=(parse_baseline, falls))
def baseline_check(ctx: RuleContext):
    """M1: every function of the current target in the grade baseline (ledger/grades.tsv, written only by `dcp
    promote`) keeps its grades: code byte -> shape / draft and shape -> draft are falls, readable -> draft is
    a fall, and a function the baseline grades that has no grade now fell too. Each fall is an error. A
    function the baseline does not list cannot fall."""
    t = ctx.project.target_name
    base = {a: r for (tt, a), r in parse_baseline(ctx.input("baseline")).items() if tt == t}
    now = {f.lo: f.value for f in ctx.facts(Kind.grade) if f.value.get("of") == "function"}
    img = ctx.image
    for a, r in sorted(base.items()):
        for what in falls(r, now.get(a)):
            at = a if img.in_image(a) else img.base
            yield ctx.conflict(Severity.error, "M1", at, at + 1, f"{r['name']} at {a:#x}: {what} (baseline ledger/grades.tsv)")
