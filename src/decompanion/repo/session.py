"""The session protocol of a solo session, layout or match-base (`dcp session start` / `dcp session wrap`): a gate at the start,
the computed report at the end. Nothing here is written by hand: the report comes from git (the session's base
commit against the working tree), the store and names.log; the only record is .dcp/session.json (git-ignored:
the base commit and the start time).

start   gate: the working tree is clean (git status, build/ and .dcp/ ignored), every unit compiles (dcp build),
        no bug or error conflict on any target, every target's link is ok (unresolved externals of undrafted
        functions and data are open work, build/link.py); then the overview: per target the unit table summary,
        the first open function (`dcp layout next`), the toolchain declaration and how much of it is probed.
wrap    build, link, check every target; promote the grade baseline (main checkout only); the report: units
        declared, joined and renamed (decl/*.dcl and names.log since the base), the fragments drafted (with their
        grades), renames, the boundary levels and status of every unit the session touched, the check before ->
        after, the next item.
"""
from __future__ import annotations

import datetime
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

FRAGMENT = re.compile(r"^src/([^/]+)/f_([0-9a-fA-F]+)\.c$")


def git(root: Path, *args) -> str:
    r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def grade_changes(root: Path, base: str, target: str, rows: list[dict]) -> list[tuple]:
    """The functions of one target whose grade differs from the baseline ledger/grades.tsv at the base commit:
    [(addr, unit, name, before 'code+readability[ level]' or None for a new fragment, after)], in address order.
    A fragment gone since the base is listed with after None."""
    def fmt(code, rd, level):
        return f"{code}+{rd}" + (f" {level}" if level else "")
    before = {}
    for line in git(root, "show", f"{base}:ledger/grades.tsv").splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) >= 7 and cols[0] == target:
            before[int(cols[1], 16)] = (cols[3], cols[2], fmt(cols[4], cols[5], cols[6]))
    out = []
    now = {}
    for r in rows:
        now[r["addr"]] = r
        b = before.get(r["addr"])
        a = fmt(r["code"], r["readability"], r.get("level") or "")
        if b is None or b[2] != a:
            out.append((r["addr"], r["unit"], r["name"], b[2] if b else None, a))
    for addr, (unit, name, b) in before.items():
        if addr not in now:
            out.append((addr, unit, name, b, None))
    return sorted(out)


def dirty(root: Path) -> list[str]:
    """The changed or untracked paths of the working tree outside build/ and .dcp/."""
    out = []
    for line in git(root, "status", "--porcelain", "--untracked-files=all").splitlines():
        path = line[3:].strip().strip('"')
        if path.startswith(("build/", ".dcp/")):
            continue
        out.append(line.rstrip())
    return out


def record_path(root: Path) -> Path:
    return Path(root) / ".dcp" / "session.json"


def save(root: Path, rec: dict):
    p = record_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec, indent=1, sort_keys=True) + "\n", newline="\n")


def load(root: Path) -> dict | None:
    p = record_path(root)
    return json.loads(p.read_text()) if p.exists() else None


@dataclass
class Changes:
    base: str
    head: str
    commits: int = 0
    drafted: list = field(default_factory=list)       # (unit, addr, file)
    removed: list = field(default_factory=list)       # fragments gone (a join moves them: not drafted, not removed)
    units_new: list = field(default_factory=list)
    units_gone: list = field(default_factory=list)
    decl_added: list = field(default_factory=list)
    decl_removed: list = field(default_factory=list)
    names: list = field(default_factory=list)         # names.log lines since the base


def changes(root: Path, base: str) -> Changes:
    """What the session changed: the base commit against the working tree (committed or not)."""
    head = git(root, "rev-parse", "--short", "HEAD").strip()
    c = Changes(base[:8], head)
    c.commits = len(git(root, "rev-list", f"{base}..HEAD").split())
    status = git(root, "diff", "--name-status", "-M", base).splitlines()
    status += [f"A\t{p}" for p in git(root, "ls-files", "--others", "--exclude-standard").split()]
    for line in status:
        parts = line.split("\t")
        kind, paths = parts[0], parts[1:]
        if kind.startswith("R") and len(paths) == 2:
            continue                                          # moved (a join or a unit rename): not drafted anew
        m = FRAGMENT.match(paths[-1]) if paths else None
        if m and kind == "A":
            c.drafted.append((m.group(1), int(m.group(2), 16), paths[-1]))
        elif m and kind == "D":
            c.removed.append(paths[-1])
    before = set(git(root, "ls-tree", "--name-only", f"{base}:src").split())
    now = {p.name for p in (Path(root) / "src").iterdir() if p.is_dir()} if (Path(root) / "src").exists() else set()
    c.units_new, c.units_gone = sorted(now - before), sorted(before - now)
    old_decl = git(root, "show", f"{base}:decl/text.dcl").splitlines()
    new_decl = (Path(root) / "decl" / "text.dcl").read_text().splitlines() if (Path(root) / "decl" / "text.dcl").exists() else []
    c.decl_added = [l for l in new_decl if l.strip() and not l.startswith("#") and l not in old_decl]
    c.decl_removed = [l for l in old_decl if l.strip() and not l.startswith("#") and l not in new_decl]
    old_names = git(root, "show", f"{base}:names.log").splitlines()
    new_names = (Path(root) / "names.log").read_text().splitlines() if (Path(root) / "names.log").exists() else []
    c.names = new_names[len(old_names):] if new_names[:len(old_names)] == old_names else [l for l in new_names if l not in old_names]
    return c


def now() -> str:
    return datetime.datetime.now().replace(microsecond=0).isoformat()


MINUTES = 30                # the length of a session


def clock(root: Path, minutes: int = MINUTES) -> dict | None:
    """The session's clock from .dcp/session.json (None without a started session): started, minutes elapsed and
    left, over once they are used up. The only clock of a session: `dcp session status`, and the first line of
    `dcp layout next` while a session runs."""
    rec = load(root)
    if not rec or not rec.get("started"):
        return None
    elapsed = (datetime.datetime.now() - datetime.datetime.fromisoformat(rec["started"])).total_seconds() / 60
    return {"session": "running", "base": (rec.get("base") or "")[:8] or None, "started": rec["started"],
            "elapsed": f"{elapsed:.0f}m", "left": f"{max(0.0, minutes - elapsed):.0f}m", "over": elapsed >= minutes}
