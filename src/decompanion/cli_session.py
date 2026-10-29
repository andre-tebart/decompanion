"""dcp: the session commands (milestone 4): session start (the gate and the overview), session wrap (build, link,
check, promote, the computed report), skills install. Same output contract as cli.py.
"""
from __future__ import annotations

import shutil
import sys
from collections import Counter
from pathlib import Path

from .cli import build_target, fmt_addr, record
from .config import Project
from .ledger.fact import Kind

SKILLS = Path(__file__).resolve().parents[2] / "skills"      # the repository's skills/ (decompanion is installed by path)


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


def state(p) -> dict:
    """The counts a session report compares: fragments, units, grades, errors."""
    from .ledger import grades as G
    rows = G.function_grades(p.store)
    units = [f for f in p.store.facts(Kind.unit) if "status" in f.value]
    return {"functions": len(rows), "byte": sum(1 for r in rows if r["code"] == "byte"),
            "readable": sum(1 for r in rows if r["readability"] == "readable"),
            "units": len(units), "separated": sum(1 for f in units if f.value["status"] == "separated"),
            "errors": sum(1 for x in p.store.conflicts() if x.severity.value in ("bug", "error")),
            "grades": dict(Counter(f"{r['code']}+{r['readability']}" for r in rows))}


def gate(args, quiet=False) -> tuple[bool, list, dict]:
    """No open toolchain or libs obligation (obligations.py); then build, check and link every target: (ok,
    [(target, project, link report)], {target: state})."""
    from .build import link as L
    from .obligations import gate_failures
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    ok, out, states = True, [], {}
    for t in p0.targets:
        p, e, rep = build_target(args, t.name, quiet=True)
        obls = gate_failures(p)
        bad_builds = [f.value["tu"] for f in p.store.facts(Kind.build) if not f.value["ok"]]
        errors = [x for x in p.store.conflicts() if x.severity.value in ("bug", "error")]
        lr = L.full_link(p) if p.store.facts(Kind.build) and p.toolchain.available() else None
        good = not obls and not bad_builds and not errors and (lr is None or lr.ok)
        ok = ok and good
        states[t.name] = state(p)
        out.append((t.name, p, lr))
        if not quiet:
            print("  " + record(target=t.name, built=rep.units, failed=",".join(bad_builds) or None, errors=len(errors),
                                link=("skipped" if lr is None else ("ok" if lr.ok else "failed")),
                                undrafted=len((lr.unresolved or {}).get("undrafted", [])) if lr else None,
                                obligations=len(obls) or None, gate="ok" if good else "FAIL"))
            for o in obls:
                print("    " + record(**o.fields()))
            for x in errors[:10]:
                print("    " + x.line())
            if lr is not None and not lr.ok:
                for k, lines in lr.unresolved.items():
                    if k != "undrafted":
                        for line in lines[:10]:
                            print(f"    unresolved {k}: {line}")
                for x in lr.errors[:5]:
                    print("    link error: " + x)
    return ok, out, states


def overview(p):
    """The unit table summary, the first open function, the toolchain level and the analyzer of one target."""
    from .ledger import layoutview as LV
    v = LV.View.load(p, p.store)
    rows = LV.unit_rows(v)
    c = Counter(r["status"] for r in rows)
    glo, ghi, _ = v.game
    covered = sum(r["range"][1] - r["range"][0] for r in rows)
    funcs = [lo for lo, _, _ in v.funcs if glo <= lo < ghi]
    drafted = sum(1 for a in funcs if a in v.sources)
    print(record(target=p.target_name, units=len(rows), separated=c.get("separated", 0), open=c.get("open", 0),
                 game=(glo, ghi), unassigned=f"{(ghi - glo) - covered:#x}", functions=len(funcs), drafted=drafted))
    for r in rows[-3:]:
        print("  " + record(unit=r["unit"], range=r["range"], status=r["status"], named_by=r["named_by"],
                            undrafted=r["undrafted"], open_bytes=r["open_bytes"]))
    recs = LV.next_records(v, 1)
    if recs:
        r = recs[0]
        print("  " + record(next=r["addr"], kind=r["kind"], size=r["size"], unit=r["unit"], analyzed=r["analyzed"]))
    else:
        print("  next: nothing open in the game code (layout complete when every unit is separated and named)")
    decl = p.toolchain_decl
    probed = [f for f in p.store.facts(Kind.toolchain) if f.run == "M.flags.proven"]
    proven = sorted(f.value["flag"] for f in probed if f.level.name == "proven")
    print("  " + record(toolchain=decl.get("compiler") or None, cflags=" ".join(decl.get("cflags") or []) or None,
                        level="declared" if not proven else "proven:" + ",".join(proven)))
    from .ledger import drafts
    n = len(drafts.entries(p.store))
    print("  " + (record(analyzer=p.analyzer.key) if p.analyzer.key == "none" and not n else record(analyzer=p.analyzer.key, drafts=n)))


def cmd_session_start(args):
    """The session gate: no open toolchain or libs obligation, a clean working tree, every unit compiles, no bug or
    error conflict, every link ok; then per target the overview (units, the first open function, the toolchain
    level) and the status tail (the open obligations: the analyzer, layout, match). Records .dcp/session.json
    (the base commit) for `dcp session wrap`. Exit 1 when the gate fails."""
    from .repo import session as S
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    root = p0.root
    head = S.git(root, "rev-parse", "HEAD").strip()
    if not head:
        return err("session start", "no commit yet: commit the project first (git add -A && git commit)")
    d = S.dirty(root)
    print(record(session="start", checkout=("worktree" if p0.main_build_dir() else "main"), base=head[:8], clean=not d))
    for line in d[:10]:
        print("  dirty " + line)
    ok, targets, states = gate(args)
    ok = ok and not d
    if not ok:
        print("gate: FAIL (resolve the obligations above (dcp status), commit or revert the working tree, fix the errors "
              "above, then start again)")
        return 1
    from .cli_decide import status_tail
    for name, p, lr in targets:
        overview(p)
        status_tail(p)
    S.save(root, {"base": head, "started": S.now(), "states": states})
    print("gate: ok. Start the timer now: a background shell `sleep 1800` (the skill's contract), then `dcp layout next`.")
    return 0


def cmd_session_wrap(args):
    """Build, link and check every target, promote the grade baseline (main checkout only), then print the
    computed report (repo/session.py) and write it to build/session/report.md. Exit 1 when the gate fails."""
    from .cli_match import cmd_promote
    from .ledger import grades as G
    from .ledger import layoutview as LV
    from .repo import session as S
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    root = p0.root
    rec = S.load(root) or {}
    base = rec.get("base") or S.git(root, "rev-parse", "HEAD").strip()
    print(record(session="wrap", base=base[:8], started=rec.get("started")))
    ok, targets, states = gate(args)
    promoted = None
    if ok and p0.main_build_dir() is None:
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_promote(args)
        promoted = buf.getvalue().strip()
    c = S.changes(root, base)
    out = [f"# layout session {S.now()[:10]} (base {c.base}, head {c.head}, {c.commits} commits)", ""]
    for name, p, lr in targets:
        b, a = (rec.get("states") or {}).get(name, {}), states[name]
        out.append(f"target {name}: errors {b.get('errors', '?')} -> {a['errors']}, fragments {b.get('functions', '?')} -> "
                   f"{a['functions']}, byte {b.get('byte', '?')} -> {a['byte']}, readable {b.get('readable', '?')} -> {a['readable']}, "
                   f"units {b.get('units', '?')} -> {a['units']} (separated {b.get('separated', '?')} -> {a['separated']}), "
                   f"link {'ok' if lr is None or lr.ok else 'FAILED'}"
                   + (f" ({len(lr.unresolved.get('undrafted', []))} undrafted externals)" if lr is not None else ""))
    out.append("")
    unit_events = [l for l in c.names if " unit " in l]
    joined = [l for l in unit_events if "why:join:" in l]
    renamed = [l for l in unit_events if l not in joined]
    out.append(f"units: declared {len(c.units_new)} ({', '.join(c.units_new) or '-'}), joined {len(joined)}, renamed {len(renamed)}, "
               f"gone {len(c.units_gone)} ({', '.join(c.units_gone) or '-'})")
    for l in joined + renamed:
        out.append("  " + l)
    for l in c.decl_added:
        out.append("  decl + " + l)
    for l in c.decl_removed:
        out.append("  decl - " + l)
    out.append("")
    p = targets[0][1]
    rows = {r["addr"]: r for r in G.function_grades(p.store)}
    out.append(f"functions drafted: {len(c.drafted)}")
    for unit, a, f in sorted(c.drafted, key=lambda t: t[1]):
        r = rows.get(a)
        g = f"{r['code']} + {r['readability']}  {r['name']}" if r else "no grade (not compiled)"
        out.append(f"  {a:#010x}  {unit:<16} {g}")
    other = [l for l in c.names if " unit " not in l]
    out.append(f"renames: {len(other)}")
    for l in other:
        out.append("  " + l)
    out.append("")
    v = LV.View.load(p, p.store)
    touched = set(c.units_new) | {u for u, _, _ in c.drafted} | {l.split(" -> ")[1].split()[0] for l in unit_events}
    out.append("units touched:")
    for r in LV.unit_rows(v):
        if r["unit"] in touched:
            out.append(f"  {r['unit']:<16} {fmt_addr(r['range'][0])}..{fmt_addr(r['range'][1])}  {r['status']:<9} start {r['start']} "
                       f"end {r['end']}  named_by {r['named_by'] or '-'}  functions {r['functions']} undrafted {r['undrafted']} "
                       f"open_bytes {r['open_bytes']}")
    recs = LV.next_records(v, 1)
    out.append("")
    out.append("next: " + (f"{fmt_addr(recs[0]['addr'])} {recs[0]['kind']} {recs[0]['size']} bytes, unit {recs[0]['unit'] or '-'}"
                           if recs else "nothing open in the game code"))
    if promoted:
        out.append("baseline: " + promoted.splitlines()[0] + " (commit ledger/grades.tsv with the session)")
    out.append("gate: " + ("ok" if ok else "FAIL"))
    text = "\n".join(out) + "\n"
    rp = root / "build" / "session" / "report.md"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(text, newline="\n")
    print(text, end="")
    return 0 if ok else 1


# ------------------------------------------------------------------------------------------------ skills
def install_skills(root: Path, force: bool = False) -> list[str]:
    """Copy the shipped skills (skills/<name>/SKILL.md of the decompanion repository) into <root>/.claude/skills/; the paths written."""
    out = []
    if not SKILLS.exists():
        return out
    for d in sorted(p for p in SKILLS.iterdir() if p.is_dir()):
        for f in sorted(q for q in d.rglob("*") if q.is_file()):
            dst = Path(root) / ".claude" / "skills" / d.name / f.relative_to(d)
            if dst.exists() and not force and dst.read_bytes() == f.read_bytes():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, dst)
            out.append(dst.relative_to(root).as_posix())
    return out


def cmd_skills_install(args):
    """Install (or update) the decompanion skills into the project's .claude/skills/."""
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    written = install_skills(p0.root, force=args.force)
    print(record(skills=len(written), into=".claude/skills"))
    for w in written:
        print("  wrote " + w)
    return 0
