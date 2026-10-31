"""dcp: the match-phase commands (build is in cli.py): grade, next, asmdiff, diffclass, escalate, stuck,
promote, accept, link, toolchain probe. Same output contract as cli.py: one record per line, key=value tokens,
addresses 0x%08x, counts before lists.
"""
from __future__ import annotations

import difflib
import sys
from collections import Counter
from pathlib import Path

from .cli import build_target, fmt_addr, open_project, parse_addr, record, refresh, target_names
from .config import ConfigError, Project
from .ledger import grades as G
from .ledger.fact import Kind


# ------------------------------------------------------------------------------------------------ lookups
def find_function(p, key: str) -> dict | None:
    """The function grade row named `key` (a function name or an address)."""
    rows = G.function_grades(p.store)
    try:
        a = parse_addr(key) if key.lower().startswith("0x") else None
    except ValueError:
        a = None
    return next((r for r in rows if r["name"] == key or (a is not None and r["addr"] == a)), None)


def compiled_code(p, row):
    """(FunctionCode, (extent, slot)) of a graded function, or (None, why): the extent and slot the grade
    compared (its dist), else the walk's or the source extent's function symbol and the next known start."""
    from .match import compare as C
    tus = p.store.tus()
    t = tus.get(row["unit"])
    if t is None or not t["ok"]:
        return None, f"unit {row['unit']} has no object (dcp build)"
    obj = C.read_object(p, t["obj_hash"])
    sym = C.function_index(obj, p.toolchain).get(row["name"]) if obj else None
    if sym is None:
        return None, f"the object of unit {row['unit']} defines no {row['name']}"
    code = obj.function_code(sym)
    d = row.get("dist") or {}
    if d.get("extent") is not None and d.get("slot") is not None:
        return code, (d["extent"], d["slot"])
    a = row["addr"]
    walk = next((f for f in p.store.facts(Kind.symbol, a, a + 1)
                 if f.run in ("S.codewalk", "L.src.extent") and f.lo == a and f.value.get("skind") == "func"), None)
    from .match import diffclass as DC
    extent = (walk.hi - walk.lo) if walk else DC.code_size(p.isa, p.image, code.code_data, code.code_mask, a, p.toolchain.fill_forms)
    from .cli_read import all_starts
    import bisect
    st = all_starts(p)
    i = bisect.bisect_right(st, a)
    nxt = st[i] if i < len(st) else p.image.end
    return code, (extent, max(extent, nxt - a))


def dist_text(d) -> str:
    if not d or d.get("ins") is None:
        return "-"
    return f"{d['ins']} ins / {d['bytes']} bytes, size {d['size']} vs {d['orig']}"


def gates(r) -> list[str]:
    out = []
    for x in r.get("failing") or []:
        k = x.split(" ", 1)[0]
        if k not in out and k[:1] in ("B", "Q"):
            out.append(k)
    return out


# ------------------------------------------------------------------------------------------------ grade
def print_function(r, verbose=True):
    print(record(fn=r["addr"], name=r["name"], unit=r["unit"], code=r["code"], readability=r["readability"],
                 level=r["level"] or "-", dist=dist_text(r.get("dist")), file=r["file"]))
    if verbose:
        for x in r.get("failing") or []:
            print("  " + x)


def cmd_grade(args):
    """The grades: without an argument the matrix and the unit table; a unit: its functions with the failing
    rules; a function (name or address): its grades, the failing rules with evidence, the distance."""
    p, e, rep = build_target(args, getattr(args, "target", None), quiet=True)
    q7 = current_lint(p, e)
    rows = G.function_grades(p.store)
    units = G.unit_grades(p.store)
    if not args.what:
        c = Counter((r["code"], r["readability"]) for r in rows)
        print(record(target=p.target_name, functions=len(rows), units=len(units)) + f"  ({q7})")
        print(f"  {'code':<8} {'draft':>7} {'readable':>9} {'total':>7}")
        for code in ("byte", "shape", "draft"):
            d, rd = c[(code, "draft")], c[(code, "readable")]
            print(f"  {code:<8} {d:>7} {rd:>9} {d + rd:>7}")
        for u in units:
            print("  " + record(unit=u["unit"], range=(u["lo"], u["hi"]), code=u["code"], readability=u["readability"],
                                functions=u["functions"], named_by=u["named_by"]))
        return 0
    unit = next((u for u in units if u["unit"] == args.what), None)
    if unit is not None:
        fs = [r for r in rows if r["unit"] == unit["unit"]]
        for r in fs:
            print_function(r)
        why = "" if unit["readability"] == "readable" else (
            "  (unit name origin guess)" if unit["named_by"] in ("guess", "-") and all(r["readability"] == "readable" for r in fs) else "")
        c = Counter(r["code"] for r in fs)
        print(record(unit=unit["unit"], functions=len(fs), code=unit["code"], readability=unit["readability"], named_by=unit["named_by"],
                     byte=c["byte"], shape=c["shape"], draft=c["draft"], readable=sum(r["readability"] == "readable" for r in fs)) + why)
        return 0
    r = find_function(p, args.what)
    if r is None:
        print(f"dcp grade: {args.what} is neither a unit nor a graded function of target {p.target_name}", file=sys.stderr)
        return 1
    print_function(r)
    if r.get("hunks"):
        print("  hunks: " + ", ".join(f"{k} {v}" for k, v in sorted(r["hunks"].items(), key=lambda kv: -kv[1])))
    print(f"  ({q7})")
    return 0


# ------------------------------------------------------------------------------------------------ next
def cmd_next(args):
    """The next functions of a queue (base by default)."""
    p, e, rep = build_target(args, getattr(args, "target", None), quiet=True)
    current_lint(p, e)
    which = "deep" if args.deep else "names" if args.names else "base"
    try:
        shard = G.shard_setting(p.root, args.shard)
    except ValueError as ex:
        print(f"dcp next: {ex}", file=sys.stderr)
        return 2
    items = G.queue(p.store, which, shard, args.unit)
    print(record(target=p.target_name, queue=which, items=len(items), shard=f"{shard[0]}/{shard[1]}" if shard else None,
                 unit=args.unit))
    for r in items[:args.n]:
        print(record(next=r["addr"], name=r["name"], unit=r["queue_unit"], section=r["section"], code=r["code"],
                     readability=r["readability"], gates=",".join(gates(r)) or None, dist=dist_text(r.get("dist")), file=r["file"]))
    if not items:
        print(f"nothing in the {which} queue" + (f" of shard {shard[0]}/{shard[1]}" if shard else ""))
    return 0


# ------------------------------------------------------------------------------------------------ asmdiff / diffclass
def listings_for(p, r):
    """(ours, the original's listings, the switch tables compare) of a graded function: the reading the grade
    takes (diffclass.compare_function)."""
    from .match import diffclass as DC
    code, ext = compiled_code(p, r)
    if code is None:
        raise ConfigError(f"{r['name']}: {ext}")
    tc = p.toolchain
    A, B, _, tables = DC.compare_function(p.isa, p.image, code, r["addr"], ext[0], ext[1], tc.fill_forms, tc.function_alignment)
    return A, B, tables


def cmd_asmdiff(args):
    """The instruction diff of one function: ours ('-') against the original ('+'), both listed at the
    original address by the ISA plugin (numbers that are image addresses and our relocated fields read X)."""
    p, e, rep = build_target(args, getattr(args, "target", None), quiet=True)
    r = find_function(p, args.name)
    if r is None:
        print(f"dcp asmdiff: no graded function {args.name}", file=sys.stderr)
        return 1
    A, B, tables = listings_for(p, r)
    a, b = [x.text for x in A], [x.text for x in B]
    if args.regs:
        a = p.isa.rename_registers(a, dict(x.split("=") for x in args.regs.split(",")))
    ops = difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
    n = sum(i2 - i1 + j2 - j1 for tag, i1, i2, j1, j2 in ops if tag != "equal")
    print(record(fn=r["addr"], name=r["name"], code=r["code"], ours=len(a), original=len(b), differing=n)
          + ("" if tables is None else "  " + record(tables="differ" if tables["diffs"] else "equal", entries=tables["entries"],
                                                     index_bytes=tables["bytes"])))
    if n:
        print("  legend: '-' ours (our object), '+' the original (the image)")
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            if i2 - i1 > 6 and not args.all:
                print(f"     ... {i2 - i1} equal instructions ...")
                continue
            for i in range(i1, i2):
                print(f"   {A[i].addr:#010x}  {a[i]}")
            continue
        for i in range(i1, i2):
            print(f"-  {A[i].addr:#010x}  {a[i]}")
        for j in range(j1, j2):
            print(f"+  {B[j].addr:#010x}  {b[j]}")
    return 0


def cmd_diffclass(args):
    """The hunks of one function's instruction diff with their classes (match/diffclass.py)."""
    from .match import diffclass as DC
    p, e, rep = build_target(args, getattr(args, "target", None), quiet=True)
    r = find_function(p, args.name)
    if r is None:
        print(f"dcp diffclass: no graded function {args.name}", file=sys.stderr)
        return 1
    A, B, tables = listings_for(p, r)
    hs, v = DC.analyse(A, B, p.isa, tables)
    print(record(fn=r["addr"], name=r["name"], ours=len(A), original=len(B), hunks=len(hs), differing=v.distance,
                 verdict="shape" if v.shape else "draft"))
    if v.frame:
        print(f"  frame: ours {v.frame[0]:#x}, the original's {v.frame[1]:#x}: the hunks of the frame-aligned diff "
              f"(stack offsets masked for the alignment)")
    if tables is not None:
        print("  " + record(tables="differ" if tables["diffs"] else "equal", entries=tables["entries"], index_bytes=tables["bytes"]))
        for x in tables["diffs"]:
            print(f"      {x}")
    if v.branches:
        print(f"  branch targets differ ({len(v.branches)}): jumps the alignment pairs go to other code")
        for x in v.branches:
            print(f"      {x}")
    for i1, i2, j1, j2, cls, info in hs:
        at = A[i1].addr if i1 < len(A) else B[j1].addr
        print(f"  {at:#010x}  {cls:<6} {i2 - i1 + j2 - j1:>4}  {info}")
        if cls == "code" and i2 - i1 + j2 - j1 <= 12:
            for x in A[i1:i2]:
                print(f"      - {x.text}")
            for x in B[j1:j2]:
                print(f"      + {x.text}")
    print("  summary: " + v.summary())
    return 0


# ------------------------------------------------------------------------------------------------ the level ladder
def cmd_level(args):
    level = args.level
    p, e = open_project(args)
    refresh(p, e)
    r = find_function(p, args.name)
    if r is None:
        print(f"dcp {level}: no graded function {args.name} (dcp build first)", file=sys.stderr)
        return 1
    if args.clear:
        action = G.set_level(p.root, r["file"], None, None, G.comment_line(r))
    else:
        if not (args.why or "").strip():
            print(f"dcp {level}: a reason is required", file=sys.stderr)
            return 1
        if level == "deep" and G.only_missing_statements(args.why):
            print(f"dcp escalate: refused: the reason names only missing statements; reconstruction is base work "
                  f"(say which leads were tried and what is left)", file=sys.stderr)
            return 1
        action = G.set_level(p.root, r["file"], level, args.why, G.comment_line(r))
    print(record(fn=r["addr"], name=r["name"], file=r["file"], action=action))
    return 0


# ------------------------------------------------------------------------------------------------ promote
def cmd_promote(args):
    """Write ledger/grades.tsv from the current grades of every target (main checkout only)."""
    p0 = Project(Path(args.root) if args.root else None)
    if p0.main_build_dir() is not None:
        print("dcp promote: refused in a worktree (the baseline is promoted on main only)", file=sys.stderr)
        return 1
    projects = []
    for t in p0.targets:
        p, e, rep = build_target(args, t.name, quiet=True)
        projects.append(p)
    path = p0.root / "ledger" / "grades.tsv"
    old = path.read_text() if path.exists() else ""
    falls = [line for p in projects for line in G.regressions(p, old)]
    accept_falls = getattr(args, "accept_falls", False)
    if falls and not accept_falls:
        print(record(promote="refused", falls=len(falls))
              + "  (promote raises entries only: dcp accept FN --to GRADE --why TEXT for a fall wanted on purpose, "
                "--accept-falls takes them all)")
        for line in falls:
            print("  fell: " + line)
        return 1
    text = G.baseline_text(projects, old, accept_falls, G.commit_of(p0.root))
    accepted = sum(1 for r in G.parse_baseline(text).values() if r["accepted"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, newline="\n")
    n = text.count("\n") - 1
    print(record(promoted=path.relative_to(p0.root).as_posix(), functions=n, targets=len(projects), falls_against_old=len(falls),
                 accepted=accepted))
    for line in falls:
        print("  fell (accepted): " + line)
    return 0


# ------------------------------------------------------------------------------------------------ accept
def cmd_accept(args):
    """Lower one function's entry of ledger/grades.tsv to the grade it fell to, with the reason (main checkout
    only): M1 then holds it there."""
    p0 = Project(Path(args.root) if args.root else None)
    if p0.main_build_dir() is not None:
        print("dcp accept: refused in a worktree (the baseline is changed on main only)", file=sys.stderr)
        return 1
    why = " ".join((args.why or "").split())
    if not why:
        print("dcp accept: a reason is required (--why TEXT)", file=sys.stderr)
        return 1
    if not args.to and not args.readability:
        print("dcp accept: --to shape|draft or --readability draft says what the entry falls to", file=sys.stderr)
        return 1
    path = p0.root / "ledger" / "grades.tsv"
    old = path.read_text() if path.exists() else ""
    p, e = open_project(args)
    refresh(p, e)
    r = find_function(p, args.name)
    if r is None:
        print(f"dcp accept: no graded function {args.name} (dcp build first)", file=sys.stderr)
        return 1
    o = G.parse_baseline(old).get((p.target_name, r["addr"]))
    if o is None:
        print(f"dcp accept: {r['name']} is not in the baseline ledger/grades.tsv: it cannot fall", file=sys.stderr)
        return 1
    to = {"code": args.to or o["code"], "readability": args.readability or o["readability"]}
    if G.at_least(to, G.grade_of(o)):
        print(f"dcp accept: {G.grade_of(to)} is no fall from the baseline's {G.grade_of(o)}", file=sys.stderr)
        return 1
    if not G.at_least(r, G.grade_of(to)):
        print(f"dcp accept: {r['name']} is {G.grade_of(r)} now, below {G.grade_of(to)}: accept the grade it has "
              f"(or fix it)", file=sys.stderr)
        return 1
    if G.CODE_RANK[to["code"]] > G.CODE_RANK[o["code"]]:      # --readability alone never raises the code
        to["code"] = o["code"]
    commit = G.commit_of(p0.root)
    note = G.accept_note(G.note_from(o["accepted"]) or G.grade_of(o), G.grade_of(to), commit, why)
    path.write_text(G.accept(old, p.target_name, r["addr"], to["code"], to["readability"], note), newline="\n")
    print(record(accepted=fmt_addr(r["addr"]), name=r["name"], target=p.target_name, was=G.grade_of(o), now=G.grade_of(to),
                 commit=commit) + "  (commit ledger/grades.tsv with the change; dcp check holds it at the accepted grade)")
    return 0


# ------------------------------------------------------------------------------------------------ link
def print_link(rep):
    print(record(link=rep.target, ok=rep.ok, objects=rep.objects, includes=rep.includes, unresolved=rep.n_unresolved,
                 errors=len(rep.errors), out=rep.out or None, cached=rep.cached, ms=rep.ms) + (f"  skipped: {rep.skipped}" if rep.skipped else ""))
    for k in ("data", "renames", "aliases", "undrafted", "library", "other"):
        lines = rep.unresolved.get(k) or []
        if lines:
            print(f"  unresolved {k}={len(lines)}")
            for line in lines[:20]:
                print("    " + line)
    for x in rep.notes:
        print("  note " + x)
    for x in rep.errors[:20]:
        print("  error " + x)


def cmd_link(args):
    from .build import link as L
    failed = False
    for name in target_names(args):
        p, e, rep = build_target(args, name, quiet=True)
        lr = L.full_link(p)
        print_link(lr)
        failed = failed or not lr.ok
    return 1 if failed else 0


# ------------------------------------------------------------------------------------------------ probe
def cmd_probe(args):
    from .build import probe as PR
    p, e, rep = build_target(args, getattr(args, "target", None), quiet=True)
    res = PR.probe(p, log=print if args.verbose else None)
    p.forget_input("probe")
    refresh(p, e)
    PR.report(p, res)
    return 0


# ------------------------------------------------------------------------------------------------ lint
def lint_target(p, e):
    from .source import lint as LI
    res = LI.lint(p)
    refresh(p, e)
    return res


def current_lint(p, e) -> str:
    """Lint again when a unit changed since the last lint (only the changed units parse) so Q7 is current; the
    note on where Q7 comes from."""
    from .source import lint as LI
    st = LI.stale(p)
    if st is None:
        return "Q7 not evaluated (no lint run: dcp lint)"
    if st and LI.available(p):
        lint_target(p, e)
        return f"Q7 linted now ({len(st)} changed units)"
    return f"Q7 stale: {len(st)} units changed, libclang not found" if st else "Q7 current"


def cmd_lint(args):
    """clang as the declaration checker of every unit of the target (source/lint.py): M6 errors, M5 cross-unit
    conflicts, M7 calls without a prototype; exit 1 on M5 / M6."""
    from .source import lint as LI
    failed = False
    for name in target_names(args):
        p, e, rep = build_target(args, name, quiet=True)
        if not LI.available(p):
            print("dcp lint: " + LI.NOT_FOUND, file=sys.stderr)
            return 2
        res = lint_target(p, e)
        ncalls = sum(len(v) for v in res["calls"].values())
        print(record(lint=p.target_name, units=len(res["units"]), parsed=res["parsed"], cached=res["cached"], m6=len(res["errors"]),
                     m5=len(res["cross"]), m7=ncalls))
        for x in res["errors"]:
            print("  M6 " + x)
        for x in res["cross"]:
            print("  M5 " + x)
        for f, cs in res["calls"].items():
            for _, c in cs:
                print(f"  M7 {f}: {c}")
        failed = failed or bool(res["errors"] or res["cross"])
    return 1 if failed else 0
