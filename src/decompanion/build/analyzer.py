"""The analyzer's export inside `dcp setup`: run the configured analyzer (analyzers/) when its export key is
stale, and replace the target's drafts with what it returned (ledger/drafts.py). No rule runs a tool: setup runs
the rules, then this, then the rules again (only L.analyzer and what reads its facts rerun).

The export key: sha256(analyzer key, image sha256, Analyzer.script_hash(), our starts). Our starts are the
function starts in the code sections (every start fact but the analyzer's own, every walked or placed function;
no inner label): the analyzer is told about them (Ghidra creates a function at each it lacks), so a new start
of ours exports again. The output directory is build/<analyzer key>/<target>/. When a start the last export was
seeded with is no longer ours (meta `drafts.starts`; the first `dcp setup` runs before the library archives are
declared, so its walk has starts the placed library code later explains), the export is `fresh`: the tool's
project is built anew instead of reused, so the drafts do not depend on the order the declarations came in.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..analyzers.base import AnalyzerError, Export
from ..ledger import drafts
from ..ledger.store import sha256


def our_starts(project) -> list[int]:
    """Our function starts in the code sections (module docstring)."""
    from ..ledger.fact import Kind, Level
    st, img = project.store, project.image
    code = [(s.va, s.end) for s in img.sections if s.holds_code]
    out, inner = set(), set()
    for f in st.facts(Kind.start):
        if f.run != "L.analyzer":
            out.add(f.lo)
    for f in st.facts(Kind.symbol):
        if f.value.get("skind") == "func" and f.level > Level.open and not f.run.startswith("M."):
            out.add(f.lo)
            inner.update(f.value.get("inner", ()))
    return sorted(a for a in out - inner if any(lo <= a < hi for lo, hi in code))


def export_key(project, starts: list[int] | None = None) -> str:
    az = project.analyzer
    starts = our_starts(project) if starts is None else starts
    return sha256(az.key, project.image.sha256, az.script_hash(), ",".join(f"{a:x}" for a in starts))


def state(project) -> str:
    """up-to-date | stale | none (never exported). The key `run` computed for this project is reused (setup's
    report follows its run; the export changes no start of ours)."""
    have = project.store.meta(drafts.EXPORT)
    if have is None:
        return "none"
    key = project.__dict__.get("_export_key") or export_key(project)
    return "up-to-date" if have == key else "stale"


def out_dir(project):
    return project.build_dir / project.analyzer.key / project.target_name


@dataclass
class Outcome:
    analyzer: str
    status: str                 # unavailable | up-to-date | exported | failed
    reason: str = ""
    where: str = ""
    stored: int = 0
    note: str = ""
    export: Export | None = None


def run(project, force: bool = False) -> Outcome:
    """Export when the configured analyzer is available and its key is stale (or forced); store the entries."""
    az = project.analyzer
    inst = az.available()
    if not inst.ok:
        return Outcome(az.key, "unavailable", inst.reason)
    starts = our_starts(project)
    key = export_key(project, starts)
    project.__dict__["_export_key"] = key
    if not force and project.store.meta(drafts.EXPORT) == key:
        return Outcome(az.key, "up-to-date", where=inst.where, note=inst.note)
    prev = project.store.meta(drafts.STARTS)
    fresh = prev is not None and not {int(x, 16) for x in prev.split(",") if x} <= set(starts)
    try:
        ex = az.export(inst, project.image, project.isa_name, starts, out_dir(project), fresh=fresh)
    except AnalyzerError as e:
        return Outcome(az.key, "failed", str(e), inst.where)
    if ex.digest and ex.digest != project.image.sha256:
        return Outcome(az.key, "failed", f"{az.key} analysed sha256 {ex.digest[:16]}, target {project.target_name} is "
                                         f"{project.image.sha256[:16]}", inst.where, export=ex)
    n = drafts.replace(project.store, project.image.sha256, ex.entries)
    project.store.set_meta(drafts.EXPORT, key)
    project.store.set_meta(drafts.STARTS, ",".join(f"{a:x}" for a in starts))
    project.forget_input("drafts")
    return Outcome(az.key, "exported", where=inst.where, stored=n, export=ex, note=inst.note)
