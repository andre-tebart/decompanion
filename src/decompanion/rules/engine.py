"""The rule engine is the core's (native/dcp_core/src/engine.rs: order, run keys, waiting, the runs; registry.rs:
every rule with its needs, outputs, inputs, ceiling and criterion). This module is its face.

- A `loader` rule (L.decl, L.src, L.analyzer) turns typed state written by a human or an external tool (a
  declarations file, the sources, the analyzer's drafts) into facts. It is the only kind of rule that may
  emit facts whose producer is a file line (`decl:<file>:<line>`, `src:<file>:<line>`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .. import native, timing

_core = native.core()
RuleError = _core.RuleError


def capstone_dll() -> str:
    """The capstone library the Python package loaded (native rules decode with the very same engine)."""
    import capstone
    return capstone._cs._name


@dataclass
class RunResult:
    rule: str
    ran: bool
    ms: int
    facts: int
    conflicts: int
    waiting: tuple = ()      # the obligations the rule waits on (it did not run its criterion)


class Engine:
    def __init__(self, project, store):
        self.project = project
        self.store = store

    def run(self, ids: Iterable[str] | None = None, force: bool = False, log=None) -> list[RunResult]:
        """Refresh the rules (all, or `ids` and what they need) of the project's current target."""
        res = _core.engine_run(self.project.core, native.source_hash(), capstone_dll(), None if ids is None else list(ids), force)
        out = []
        for rid, ran, ms, nf, nc, waits, ms_run, ms_rec in res:
            out.append(RunResult(rid, ran, ms, nf, nc, tuple(waits)))
            if ran and not waits:
                timing.add("refresh.rules", ms)
                timing.add(f"rule.{rid}", ms)
                timing.add(f"rule.{rid}.run", ms_run)
                timing.add(f"rule.{rid}.record", ms_rec)
            if log and ran:
                log(f"waiting {rid}: {', '.join(waits)}" if waits else f"ran {rid}: {nf} facts, {nc} conflicts, {ms} ms")
        return out
