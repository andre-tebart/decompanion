"""The rule engine: every computed fact comes from a registered rule, every rule run is memoised by the hash of
its inputs, and the code of the rule itself is part of that hash.

A rule is a function decorated with @rule:

    @rule("S.fill", version="1", ceiling=Level.derived, needs=("S.sections", "kind:symbol"), outputs=("symbol",),
          inputs=())
    def fill(ctx: RuleContext):
        '''<the exact criterion, as prose; `dcp rules` prints it>'''
        ...
        yield Fact(...)

- `needs` are the rules whose current facts this rule may read (`ctx.facts(kind)` returns only facts of those
  runs). `kind:symbol` stands for every registered rule that lists `symbol` in its outputs, so a rule that
  closes a kind (the catch-all, the byte map) needs no list of producers. Dependencies by rule, not by kind,
  keep the graph acyclic by construction: a rule cannot read the kind it produces.
- `inputs` are named external inputs the project provides (image, config, libs, decl, src, ...). The image and
  the plugins (the code behind the image, toolchain, object-format and instruction-set seams, and which of
  them the target selects) are inputs of every rule.
- `ceiling` is the best level the criterion can justify; a yielded fact above it is a programming error. The
  rule lowers the level itself with min_level() when it rests on a premise fact (a declared boundary, a
  derived start): the engine cannot know which facts were premises and which were merely verified.
- The run key is sha256(code of the function, version, out_hash of each needed run, hash of each input). A
  rule whose key matches a stored run is skipped; `dcp rules` shows which ran and how long they took.
  `helpers` (functions or modules the rule calls) join the code hash, so editing a helper reruns the rule.
- An input may be absent until a human declares it (Project.waiting: `libs` until the archives are declared,
  `toolchain` until the compiler and linker builds are). A rule reading such an input waits: its criterion does
  not run, the engine records an empty run keyed by the obligations it waits on (obligations.py), so the rules
  that need it run on nothing from it; `dcp rules` shows `waiting: <obligation>`. The declaration changes the
  key, the rule runs, and everything downstream reruns as usual.
- A `loader` rule (L.decl, L.src, L.analyzer) turns typed state written by a human or an external tool (a
  declarations file, the sources, the analyzer's drafts) into facts. It is the only kind of rule that may
  emit facts whose producer is a file line (`decl:<file>:<line>`, `src:<file>:<line>`) instead of the rule:
  ctx.declared() stamps them at level declared and refuses a missing reason.
"""
from __future__ import annotations

import hashlib
import inspect
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .. import timing
from ..ledger.fact import Conflict, Fact, Kind, Level
from ..ledger.store import Store, sha256


@dataclass
class Rule:
    id: str
    version: str
    ceiling: Level
    needs: tuple[str, ...]
    outputs: tuple[str, ...]
    inputs: tuple[str, ...]
    fn: Callable
    doc: str
    code_hash: str
    phase: str = ""
    loader: bool = False

    @property
    def name(self):
        return f"rule:{self.id}@{self.version}"


RULES: dict[str, Rule] = {}


def rule(id: str, *, version: str, ceiling: Level, outputs: tuple[str, ...] = (), needs: tuple[str, ...] = (),
         inputs: tuple[str, ...] = (), phase: str = "", helpers: tuple = (), loader: bool = False):
    def deco(fn):
        if id in RULES:
            raise RuntimeError(f"rule {id} registered twice")
        src = inspect.getsource(fn) + "".join(inspect.getsource(h) for h in helpers)
        if loader and Level(ceiling) > Level.declared:
            raise RuntimeError(f"loader rule {id} with ceiling {Level(ceiling)}: loaders declare")
        RULES[id] = Rule(id, version, Level(ceiling), tuple(needs), tuple(outputs), tuple(inputs), fn,
                         inspect.getdoc(fn) or "", hashlib.sha256(src.encode()).hexdigest()[:16], phase or id.split(".")[0],
                         loader)
        return fn
    return deco


class RuleError(RuntimeError):
    pass


class RuleContext:
    """What a rule may see: the project, the image, the facts of the rules it needs, its external inputs."""

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

    def conflicts(self, check: str | None = None) -> list[Conflict]:
        """Current conflicts of the needed rules (their runs' out_hash covers them), optionally of one check."""
        if not self._needed:
            raise RuleError(f"{self.rule.id} reads conflicts but needs no rule")
        return [c for c in self.store.conflicts(rules=self._needed) if check is None or c.check == check]

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

    def declared(self, lo: int, hi: int, kind: Kind | str, value: dict, by: str, reason: str) -> Fact:
        """A declared fact whose producer is a line of typed state (only loader rules may emit these)."""
        kind = Kind(kind)
        if not self.rule.loader:
            raise RuleError(f"{self.rule.id} is not a loader: it may not emit {by} facts")
        if kind not in self._kinds_ok:
            raise RuleError(f"{self.rule.id} emits {kind} but lists outputs {self.rule.outputs}")
        if not by.startswith(("decl:", "src:")):
            raise RuleError(f"{self.rule.id}: a declared fact's producer must be decl:<file>:<line> or src:<file>:<line>, not {by!r}")
        if not reason or not reason.strip():
            raise RuleError(f"{self.rule.id}: declared {kind} at {lo:#x} ({by}) without a reason")
        return Fact(lo, hi, kind, value, Level.declared, by, reason)

    def conflict(self, severity, check: str, lo: int, hi: int, message: str, a: str = "", b: str = "") -> Conflict:
        return Conflict(severity, check, lo, hi, message, a, b)

    def blob(self, hash_: str):
        return self.store.blob(hash_)

    def put_blob(self, hash_: str, kind: str, data: bytes):
        self.store.put_blob(hash_, kind, data)


@dataclass
class RunResult:
    rule: str
    ran: bool
    ms: int
    facts: int
    conflicts: int
    waiting: tuple = ()      # the obligations the rule waits on (it did not run its criterion)


class Engine:
    def __init__(self, project, store: Store):
        self.project = project
        self.store = store

    # ------------------------------------------------------------------ graph
    def resolve_needs(self, r: Rule) -> tuple[str, ...]:
        out = []
        for n in r.needs:
            if n.startswith("kind:"):
                k = n[5:]
                out.extend(x.id for x in RULES.values() if k in x.outputs and x.id != r.id)
            else:
                if n not in RULES:
                    raise RuleError(f"{r.id} needs unknown rule {n}")
                out.append(n)
        return tuple(dict.fromkeys(out))

    def order(self, ids: Iterable[str] | None = None) -> list[Rule]:
        """Rules in dependency order (Kahn), restricted to `ids` and everything they need."""
        wanted = set(RULES) if ids is None else set()
        if ids is not None:
            stack = list(ids)
            while stack:
                i = stack.pop()
                if i in wanted:
                    continue
                wanted.add(i)
                stack.extend(self.resolve_needs(RULES[i]))
        deps = {i: set(self.resolve_needs(RULES[i])) & wanted for i in wanted}
        done, out = set(), []
        while deps:
            ready = sorted(i for i, d in deps.items() if d <= done)
            if not ready:
                raise RuleError("cycle among rules: " + ", ".join(sorted(deps)))
            for i in ready:
                out.append(RULES[i])
                done.add(i)
                del deps[i]
        return out

    # ------------------------------------------------------------------ running
    def input_hash(self, r: Rule, needed: tuple[str, ...]) -> str:
        parts = [r.code_hash, r.version, self.project.input_hash("image"), self.project.input_hash("plugins")]
        for n in needed:
            cur = self.store.current_run(n)
            if cur is None:
                raise RuleError(f"{r.id} needs {n}, which has no current run")
            parts.append(f"{n}={cur[2]}")
        for name in r.inputs:
            parts.append(f"{name}={self.project.input_hash(name)}")
        return sha256(*parts)

    def waiting(self, r: Rule) -> tuple[str, ...]:
        """The obligations a rule waits on: those of its inputs that are absent until a human declares them
        (Project.waiting; obligations.py names them)."""
        w = getattr(self.project, "waiting_for", None)      # a project without declarations waits on nothing
        return w(r.inputs) if w is not None else ()

    def run(self, ids: Iterable[str] | None = None, force: bool = False, log=None) -> list[RunResult]:
        results = []
        for r in self.order(ids):
            needed = self.resolve_needs(r)
            waits = self.waiting(r)
            if waits:
                # an empty run keyed by what it waits on: the rules that need it run on its (empty) output, and
                # the declaration that ends the wait changes the key
                ih = sha256(r.code_hash, r.version, "waiting", *waits)
                found = self.store.find_run(r.id, ih)
                if found is not None:
                    where, run_id, _ = found
                    cur = self.store.current_run(r.id)
                    if cur is None or cur[0] != run_id or where != "main":
                        self.store.make_current(r.id, where, run_id)
                    results.append(RunResult(r.id, False, 0, 0, 0, waits))
                    continue
                self.store.record_run(r.id, r.version, r.code_hash, ih, [], [], 0)
                results.append(RunResult(r.id, True, 0, 0, 0, waits))
                if log:
                    log(f"waiting {r.id}: {', '.join(waits)}")
                continue
            ih = self.input_hash(r, needed)
            found = None if force else self.store.find_run(r.id, ih)
            if found is not None:
                where, run_id, _ = found
                cur = self.store.current_run(r.id)
                if cur is None or cur[0] != run_id or where != "main":
                    self.store.make_current(r.id, where, run_id)
                results.append(RunResult(r.id, False, 0, 0, 0))
                continue
            t0 = time.perf_counter()
            ctx = RuleContext(self, r, needed)
            facts, conflicts = [], []
            for item in r.fn(ctx) or ():
                if isinstance(item, Fact):
                    facts.append(item)
                elif isinstance(item, Conflict):
                    conflicts.append(item)
                else:
                    raise RuleError(f"{r.id} yielded {type(item).__name__}")
            ms = int((time.perf_counter() - t0) * 1000)
            t1 = time.perf_counter()
            self.store.record_run(r.id, r.version, r.code_hash, ih, facts, conflicts, ms)
            rec = (time.perf_counter() - t1) * 1000
            timing.add("refresh.rules", ms)
            timing.add("refresh.record", rec)
            timing.add(f"rule.{r.id}", ms)
            timing.add(f"record.{r.id}", rec)
            results.append(RunResult(r.id, True, ms, len(facts), len(conflicts)))
            if log:
                log(f"ran {r.id}: {len(facts)} facts, {len(conflicts)} conflicts, {ms} ms")
        return results

    def status(self):
        """[(rule, current run?, ms, facts, waiting obligations)] for `dcp rules`."""
        rows = []
        for r in self.order():
            cur = self.store.current_run(r.id)
            n = 0
            ms = 0
            if cur:
                n = self.store.db.execute("SELECT COUNT(*) FROM fact WHERE run_id=?", (cur[0],)).fetchone()[0]
                ms = self.store.db.execute("SELECT ms FROM run WHERE id=?", (cur[0],)).fetchone()[0]
            rows.append((r, cur is not None, ms, n, self.waiting(r)))
        return rows
