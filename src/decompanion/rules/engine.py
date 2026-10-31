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
from ..ledger.fact import Level

_core = native.core()
RuleError = _core.RuleError


@dataclass
class Rule:
    id: str
    version: str
    ceiling: Level
    phase: str
    loader: bool
    needs: tuple[str, ...]          # resolved: `kind:` needs expanded
    outputs: tuple[str, ...]
    inputs: tuple[str, ...]
    doc: str

    @property
    def name(self):
        return f"rule:{self.id}@{self.version}"


def _rules(ids=None) -> list[Rule]:
    return [Rule(i, v, Level(c), ph, ld, tuple(n), tuple(o), tuple(ins), doc)
            for i, v, c, ph, ld, n, o, ins, doc in _core.engine_order(None if ids is None else list(ids))]


RULES: dict[str, Rule] = {r.id: r for r in _rules()}
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

    def resolve_needs(self, r: Rule) -> tuple[str, ...]:
        return r.needs

    def order(self, ids: Iterable[str] | None = None) -> list[Rule]:
        """Rules in dependency order, restricted to `ids` and everything they need."""
        return [RULES[r.id] for r in _rules(ids)]

    def waiting(self, r: Rule) -> tuple[str, ...]:
        """The obligations a rule waits on: those of its inputs that are absent until a human declares them."""
        return self.project.waiting_for(r.inputs)

    def run(self, ids: Iterable[str] | None = None, force: bool = False, log=None) -> list[RunResult]:
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

    def status(self):
        """[(rule, current run?, ms, facts, waiting obligations)] for `dcp rules`."""
        rows = []
        for r in self.order():
            cur = self.store.current_run(r.id)
            n, ms = self.store.run_stats(cur[0]) if cur else (0, 0)
            rows.append((r, cur is not None, ms, n, self.waiting(r)))
        return rows
