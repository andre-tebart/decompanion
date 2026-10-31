"""dcp: the session commands (milestone 4): session start (the gate and the overview), session wrap (build, link,
check, promote, the computed report), skills install. Same output contract as cli.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

from . import native
from .cli import build_target, record
from .config import Project
from .ledger.fact import Kind

DCP_ROOT = Path(__file__).resolve().parents[2]      # the decompanion repository (installed by path): its skills/
MINUTES = 30                                                  # the length of a session (the core's session.rs)


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


def state(p) -> dict:
    """The counts a session report compares: functions, units, grades, errors (the core's session.rs)."""
    return native.core().session_state(p.core)


def gate(args, quiet=False) -> tuple[bool, list, dict]:
    """No open toolchain or libs obligation (decide.rs); then build, check and link every target: (ok,
    [(target, project, link report)], {target: state})."""
    from .cli_decide import gate_failures
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    ok, out, states = True, [], {}
    for t in p0.targets:
        p, e, rep = build_target(args, t.name, quiet=True)
        obls = gate_failures(p)
        bad_builds = [f.value["tu"] for f in p.store.facts(Kind.build) if not f.value["ok"]]
        errors = [x for x in p.store.conflicts() if x.severity.value in ("bug", "error")]
        lr = native.core().link_command(p.core) if p.store.facts(Kind.build) and p.core.toolchain_available() else None
        good = not obls and not bad_builds and not errors and (lr is None or lr[1])
        ok = ok and good
        states[t.name] = state(p)
        out.append((t.name, p, lr))
        if not quiet:
            print("  " + record(target=t.name, built=rep.units, failed=",".join(bad_builds) or None, errors=len(errors),
                                link=("skipped" if lr is None else ("ok" if lr[1] else "failed")),
                                undrafted=lr[3] if lr else None,
                                obligations=len(obls) or None, gate="ok" if good else "FAIL"))
            for o in obls:
                print("    " + o)
            for x in errors[:10]:
                print("    " + x.line())
            for line in lr[4] if lr is not None else ():
                print(line)
    return ok, out, states


def overview(p):
    """The unit table summary, the first open function, the toolchain level and the analyzer of one target."""
    for line in native.core().session_overview(p.core, p.analyzer.key):
        print(line)


def cmd_session_start(args):
    """The session gate: no open toolchain or libs obligation, a clean working tree, every unit compiles, no bug or
    error conflict, every link ok; then per target the overview (units, the first open function, the toolchain
    level) and the status tail (the open obligations: the analyzer, layout, match). Records .dcp/session.json
    (the base commit) for `dcp session wrap`. Exit 1 when the gate fails."""
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    root = str(p0.root)
    head = native.core().session_head(root)
    if not head:
        return err("session start", "no commit yet: commit the project first (git add -A && git commit)")
    d = native.core().session_dirty(root)
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
    native.core().session_save(root, head, states)
    print(f"gate: ok. The session clock runs ({MINUTES} minutes): `dcp session status`, and the first line of "
          "`dcp layout next`; wrap up once it says over=yes.")
    return 0


def cmd_session_status(args):
    """The session's clock (the core's session.rs): base commit, start time, minutes elapsed and left of
    --minutes; `over=yes` once they are used up."""
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    c = native.core().session_clock(str(p0.root), args.minutes)
    if c is None:
        return err("session status", "no session started (dcp session start)")
    print(c[0])
    return 0


def cmd_session_wrap(args):
    """Build, link and check every target, promote the grade baseline (main checkout only), then print the
    computed report (the core's session.rs) and write it to build/session/report.md. Exit 1 when the gate fails."""
    import contextlib
    import io
    from .cli_match import cmd_promote
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    root = str(p0.root)
    base, started = native.core().session_record(root)
    base = base or native.core().session_head(root)
    print(record(session="wrap", base=base[:8], started=started))
    ok, targets, states = gate(args)
    promoted, refused = None, False
    if ok and p0.main_build_dir() is None:          # the gate passed M1, so promote finds no fall; it still checks
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            refused = cmd_promote(args) != 0
        promoted = buf.getvalue().strip()
        ok = ok and not refused
    links = [(name, p.core, None if lr is None else lr[1], None if lr is None else lr[3])
             for name, p, lr in targets]
    print(native.core().session_report(root, base, links, states, promoted, refused, ok), end="")
    return 0 if ok else 1


# ------------------------------------------------------------------------------------------------ skills
def cmd_skills_install(args):
    """Install (or update) the decompanion skills into the project's .claude/skills/."""
    p0 = Project(Path(args.root) if getattr(args, "root", None) else None)
    written = native.core().skills_install(str(DCP_ROOT), str(p0.root), args.force)
    print(record(skills=len(written), into=".claude/skills"))
    for w in written:
        print("  wrote " + w)
    return 0
