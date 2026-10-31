"""The rule engine is the core's (native/dcp_core/src/engine.rs: order, run keys, waiting, the runs; registry.rs:
every rule with its needs, outputs, inputs, ceiling and criterion). This module is its face, and the front end
the engine calls back for what the core does not compute yet (Front): the source scan's digest and pieces, the
tree's raw macros and described addresses, the last lint, the units' text hashes, and the rules whose code is still
Python (registered here with @rule: M.compile, M.flags.proven).

A rule (any kind) yields facts and conflicts and nothing else; a Python rule sees the project only through its
RuleContext: the facts of the rules it needs, the named external inputs it declares.

- A `loader` rule (L.decl, L.src, L.analyzer) turns typed state written by a human or an external tool (a
  declarations file, the sources, the analyzer's drafts) into facts. It is the only kind of rule that may
  emit facts whose producer is a file line (`decl:<file>:<line>`, `src:<file>:<line>`).
"""
from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass
from typing import Callable, Iterable

from .. import native, timing
from ..ledger.fact import Conflict, Fact, Kind, Level

_core = native.core()
RuleError = _core.RuleError


@dataclass
class Rule:
    id: str
    version: str
    ceiling: Level
    phase: str
    loader: bool
    python: bool
    needs: tuple[str, ...]          # resolved: `kind:` needs expanded
    outputs: tuple[str, ...]
    inputs: tuple[str, ...]
    doc: str

    @property
    def name(self):
        return f"rule:{self.id}@{self.version}"


def _rules(ids=None) -> list[Rule]:
    return [Rule(i, v, Level(c), ph, ld, py, tuple(n), tuple(o), tuple(ins), doc)
            for i, v, c, ph, ld, py, n, o, ins, doc in _core.engine_order(None if ids is None else list(ids))]


RULES: dict[str, Rule] = {r.id: r for r in _rules()}
PY_RULES: dict[str, tuple[Callable, str]] = {}          # id -> (function, code hash) of the rules still in Python


def rule(id: str, *, helpers: tuple = ()):
    """Register the Python code of a rule the registry marks `python` (its code hash: its source and helpers')."""
    def deco(fn):
        if id not in RULES or not RULES[id].python:
            raise RuntimeError(f"rule {id} is not a Python rule of the registry")
        src = inspect.getsource(fn) + "".join(inspect.getsource(h) for h in helpers)
        PY_RULES[id] = (fn, hashlib.sha256(src.encode()).hexdigest()[:16])
        return fn
    return deco


def capstone_dll() -> str:
    """The capstone library the Python package loaded (native rules decode with the very same engine)."""
    import capstone
    return capstone._cs._name


class RuleContext:
    """What a Python rule may see: the project, the image, the facts of the rules it needs, its external inputs."""

    def __init__(self, engine: Engine, rule_: Rule, needed: tuple[str, ...]):
        self.engine = engine
        self.rule = rule_
        self.project = engine.project
        self.image = engine.project.image
        self.store = engine.store
        self._needed = needed
        self._kinds_ok = frozenset(Kind(o) for o in rule_.outputs)

    def facts(self, kind: Kind | str, lo: int | None = None, hi: int | None = None):
        """Current facts of the needed rules, of one kind, intersecting [lo, hi)."""
        if not self._needed:
            raise RuleError(f"{self.rule.id} reads facts but needs no rule")
        return self.store.facts(kind, lo, hi, rules=self._needed)

    def input(self, name: str):
        """The object of a named external input (declared in `inputs`)."""
        if name not in self.rule.inputs:
            raise RuleError(f"{self.rule.id} reads input {name!r} it did not declare")
        return self.project.input(name)

    def fact(self, lo: int, hi: int, kind: Kind | str, value: dict, level: Level, reason: str | None = None) -> Fact:
        """A fact produced by this rule (the producer is stamped; the level is capped by the ceiling)."""
        kind = Kind(kind)
        if kind not in self._kinds_ok:
            raise RuleError(f"{self.rule.id} emits {kind} but lists outputs {self.rule.outputs}")
        if level > self.rule.ceiling:
            raise RuleError(f"{self.rule.id} emits {kind} at {lo:#x} as {level} above its ceiling {self.rule.ceiling}")
        return Fact(lo, hi, kind, value, level, self.rule.name, reason)

    def conflict(self, severity, check: str, lo: int, hi: int, message: str, a: str = "", b: str = "") -> Conflict:
        return Conflict(severity, check, lo, hi, message, a, b)


@dataclass
class RunResult:
    rule: str
    ran: bool
    ms: int
    facts: int
    conflicts: int
    waiting: tuple = ()      # the obligations the rule waits on (it did not run its criterion)


class Front:
    """What the core's engine asks the front end for (engine.rs module docstring)."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.p = engine.project

    def code_hash(self, rule_id: str) -> str:
        return PY_RULES[rule_id][1]

    def input_hash(self, name: str) -> str:
        return self.p.input_hash(name)

    def front_inputs(self, rule_id: str) -> dict:
        from ..build import compile as build_compile
        from ..ledger import srcscan
        if rule_id == "M.lint":
            return {"units": {a.unit: a.src_hash for a in build_compile.plan(self.p)}}
        tree = self.p.input_hash("src")
        out = {"scan": srcscan.native_pieces(srcscan.scan(self.p.root, tree))}
        if rule_id == "G.grade":
            from .grade import context
            raw, described = context(str(self.p.root), tree)
            lint = self.p.input("lint")
            current = {a.unit: a.src_hash for a in build_compile.plan(self.p)} if lint else {}
            calls = lint.get("calls") if lint else None
            out.update(raw=sorted(raw), described=sorted(described),
                       lint_calls=None if calls is None else {f: [tuple(c) for c in cs] for f, cs in calls.items()},
                       linted=sorted(u for u, h in (lint or {}).get("units", {}).items() if current.get(u) == h))
        return out

    def run_python(self, rule_id: str, needed: list[str]):
        ctx = RuleContext(self.engine, RULES[rule_id], tuple(needed))
        facts, conflicts = [], []
        for item in PY_RULES[rule_id][0](ctx) or ():
            if isinstance(item, Fact):
                facts.append(item)
            elif isinstance(item, Conflict):
                conflicts.append(item)
            else:
                raise RuleError(f"{rule_id} yielded {type(item).__name__}")
        return facts, conflicts


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
        res = _core.engine_run(self.project.core, native.source_hash(), capstone_dll(), Front(self),
                               None if ids is None else list(ids), force)
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
