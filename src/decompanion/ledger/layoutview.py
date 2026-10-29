"""What `dcp layout next|units|unit propose` print, computed from the current facts of one target's store.

Nothing here decides anything new: the units are L.unit.extent's facts, the evidence L.analyze's, the checks
are the pure functions of rules/layout.py (run again on the units as a proposal would make them).
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from ..rules import layout as L
from . import ghidra
from .fact import Kind, Level


@dataclass
class View:
    """The layout-relevant facts of one store, indexed."""
    project: object
    store: object
    game: tuple = (0, 0, Level.open)
    funcs: list = field(default_factory=list)          # [(lo, hi, fact)] of function symbols above open
    syms: list = field(default_factory=list)
    starts: dict = field(default_factory=dict)         # addr -> [start facts]
    sources: dict = field(default_factory=dict)        # addr -> source fact (functions)
    units: list = field(default_factory=list)          # game units (UnitX)
    unit_facts: list = field(default_factory=list)
    lits: list = field(default_factory=list)
    leaks: list = field(default_factory=list)
    fills: dict = field(default_factory=dict)          # start -> fill evidence value
    bounds: list = field(default_factory=list)

    @classmethod
    def load(cls, project, store):
        v = cls(project, store)
        img = project.image
        v.syms = [f for f in store.facts(Kind.symbol) if not f.run.startswith("M.")]   # the match phase repeats the walk's functions
        v.game = L.game_range(img, L.lib_starts_of(v.syms))
        v.funcs = L.functions_of(v.syms)
        for f in store.facts(Kind.start):
            v.starts.setdefault(f.lo, []).append(f)
        for f in store.facts(Kind.source):
            if f.value.get("what") == "func":
                v.sources[f.lo] = f
        v.unit_facts = [f for f in store.facts(Kind.unit) if "status" in f.value]
        v.units = L.game_units(v.unit_facts)
        ev = store.facts(Kind.evidence)
        v.lits = L.lits_of(ev)
        v.leaks = L.leaks_of(ev)
        v.fills = {f.lo: f.value for f in ev if f.value.get("ekind") == "fill"}
        v.bounds = L.bounds_of(store.facts(Kind.boundary))
        return v

    # ------------------------------------------------------------------ items of the game code
    def items(self):
        """The game code in address order as (lo, hi, what, fact): func (a function symbol), start (a declared
        start inside unknown code), unknown (open bytes no start explains), other symbols skipped."""
        glo, ghi, _ = self.game
        out = []
        for f in self.syms:
            if not (glo <= f.lo < ghi):
                continue
            sk = f.value.get("skind")
            if sk == "func" and f.level > Level.open:
                out.append((f.lo, f.hi, "func", f))
            elif sk == "unknown.code":
                pos = f.lo
                inner = sorted(a for a in self.starts if f.lo <= a < f.hi)
                for a in inner:
                    if a > pos:
                        out.append((pos, a, "unknown", f))
                    nxt = next((b for b in inner if b > a), f.hi)
                    out.append((a, nxt, "start", f))
                    pos = nxt
                if pos < f.hi:
                    out.append((pos, f.hi, "unknown", f))
        out.sort(key=lambda t: t[0])
        return out

    def symbol_kind(self, a):
        """The skind of the symbol (not the match phase's) that starts at a, or None."""
        if not hasattr(self, "_skind_at"):
            self._skind_at = {}
            for f in self.syms:
                self._skind_at.setdefault(f.lo, f.value.get("skind"))
        return self._skind_at.get(a)

    def unit_at(self, a):
        i = L.unit_index(self.units)(a)
        return self.units[i] if i is not None else None

    def unit_fact(self, u):
        return next((f for f in self.unit_facts if f.lo == u.lo and f.value["tu"] == u.tu), None)

    def callers(self, a):
        out = []
        at = L.container(self.funcs)
        for r in self.store.facts(Kind.ref):
            if r.value.get("to") == a and r.value["rkind"] in ("call", "tail", "immediate", "reloc", "operand"):
                fn = at(r.lo)
                out.append((r.lo, r.value["rkind"], fn[0] if fn else None))
        out.sort()
        return out

    def lit_blocks(self):
        """Per game unit and data section: [min, max) of the literals whose first user lies in the unit."""
        at = L.unit_index(self.units)
        blocks = {}
        for l in self.lits:
            i = at(l.first)
            if i is None:
                continue
            k = (i, l.section)
            lo, hi = blocks.get(k, (l.lo, l.hi))
            blocks[k] = (min(lo, l.lo), max(hi, l.hi))
        return blocks

    def first_lits(self, fn):
        return sorted((l for l in self.lits if l.first == fn), key=lambda l: l.lo)

    def lit_jump(self, fn):
        """For each section: (this function's lowest first literal) - (the highest literal first used by an
        earlier function): a big forward jump skips another unit's block (D8)."""
        mine = self.first_lits(fn)
        out = {}
        for sec in sorted({l.section for l in mine}):
            lo = min(l.lo for l in mine if l.section == sec)
            prev = [l.hi for l in self.lits if l.section == sec and l.first < fn]
            out[sec] = (lo - max(prev)) if prev else None
        return out


def fmt(a):
    return f"{a:#010x}"


def fmt_range(lo, hi):
    return f"{lo:#010x}..{hi:#010x}"


def next_records(v: View, count: int = 1, start: int | None = None):
    """The first `count` open items of the game code from `start`: a function without a source fragment, a
    declared start in unknown code, or unknown code no start explains. One record per item (a dict), with its
    evidence lines."""
    items = v.items()
    starts_sorted = sorted({lo for lo, _, w, _ in items if w in ("func", "start")} | {v.game[1]})
    img_sha = v.project.image.sha256
    out = []
    for lo, hi, what, f in items:
        if start is not None and lo < start:
            continue
        if what in ("func", "start") and lo in v.sources:
            continue
        u = v.unit_at(lo)
        k = bisect.bisect_right(starts_sorted, lo)
        nxt = starts_sorted[k] if k < len(starts_sorted) else v.game[1]
        rec = {"addr": lo, "kind": what, "size": (nxt - lo) if what != "unknown" else (hi - lo), "next_start": nxt,
               "unit": u.tu if u else None, "unit_status": (v.unit_fact(u).value["status"] if u else None),
               "ghidra": ghidra.draft(v.store, img_sha, lo) is not None, "lines": []}
        if what == "func":
            rec["extent"] = (f.lo, f.hi)
        for s in v.starts.get(lo, []):
            rec["lines"].append(("start", {"how": s.value["how"], "level": s.level.name, "by": s.by}))
        for site, rk, fn in v.callers(lo):
            cu = v.unit_at(fn) if fn is not None else None
            rec["lines"].append(("caller", {"site": site, "rkind": rk, "fn": fn, "unit": cu.tu if cu else None}))
        fl = v.fills.get(lo)
        if fl:
            rec["lines"].append(("fill", {"before": fl["pre"], "run": fl["run"]}))
        blocks = v.lit_blocks()
        here = L.unit_index(v.units)(lo)
        for l in v.first_lits(lo):
            inblk = [v.units[i].tu for (i, sec), (blo, bhi) in blocks.items()
                     if sec == l.section and blo <= l.lo < bhi and i != here and v.units[i].lo < lo]
            rec["lines"].append(("literal", {"range": (l.lo, l.hi), "section": l.section, "data_refs": l.data_refs,
                                             "earlier_unit_block": inblk[0] if inblk else None,
                                             "text": v.project.image.cstr(l.lo)[:48].decode("latin-1")}))
        for sec, j in v.lit_jump(lo).items():
            rec["lines"].append(("literal_jump", {"section": sec, "jump": j}))
        for l in v.leaks:
            if l.fn == lo:
                rec["lines"].append(("leak", {"path": l.path, "header": l.header}))
        out.append(rec)
        if len(out) >= count:
            break
    return out


def undrafted(v: View):
    """L2: function starts inside game units without a source fragment (informational)."""
    out = []
    for lo, hi, what, f in v.items():
        if what in ("func", "start") and lo not in v.sources and v.unit_at(lo) is not None:
            out.append(lo)
    return out


def unit_rows(v: View):
    rows = []
    for f in sorted(v.unit_facts, key=lambda f: f.lo):
        val = f.value
        leaks = sorted({l.path for l in v.leaks if f.lo <= l.fn < f.hi and not l.header})
        rows.append({"unit": val["tu"], "range": (f.lo, f.hi), "status": val["status"], "start": val["start_level"],
                     "end": val["end_level"], "named_by": val.get("named_by"), "open_bytes": val["open_bytes"],
                     "functions": val["functions"], "sourced": val["sourced"], "undrafted": val["functions"] - val["sourced"],
                     "dead_bytes": val.get("dead_bytes", 0), "walk_conflicts": val.get("walk_conflicts", 0),
                     "start_by": val["start_by"], "end_by": val["end_by"], "leaks": leaks, "level": f.level.name})
    return rows


@dataclass
class Proposal:
    lo: int
    hi: int | None
    name: str
    lines: list          # decl lines (text) to write
    table: list          # evidence rows per function
    new_issues: list
    old_issues: list


def all_issues(v: View, units, bounds, srcs):
    """L3 / L4 / L7 / L8 issues for a set of units and boundaries."""
    starts = set(v.starts) | {lo for lo, _, _ in v.funcs}
    for lo, hi, f in v.funcs:
        starts.update(f.value.get("inner", ()))
    fills = sorted((f.lo, f.hi) for f in v.syms if f.value.get("skind") == "fill")
    funcs = [(lo, hi) for lo, hi, _ in v.funcs]
    return (L.lit_issues(units, v.lits) + L.boundary_issues(bounds, starts, funcs, fills, v.game)
            + L.leak_issues(units, v.leaks))


def propose(v: View, lo: int, hi: int | None, name: str) -> Proposal:
    """Evaluate a unit lo..hi named `name` against the current units: compute the units with the proposed
    boundaries added, run L3 / L4 / L7 / L8 on them, and keep the issues the current state does not have."""
    glo, ghi, _ = v.game
    srcs = L.srcfns_of(v.store.facts(Kind.source))
    fstarts = [a for a, _, _ in v.funcs if glo <= a < ghi]
    cur_units, cur_l7 = L.compute_units(v.game, v.bounds, srcs, fstarts)
    cur = cur_l7 + all_issues(v, cur_units, v.bounds, srcs)
    by = "proposal"
    new_bounds = list(v.bounds) + [L.Bound(lo, "start", name, by)]
    units, l7 = L.compute_units(v.game, new_bounds, srcs, fstarts)
    lines = [(lo, "start")]
    if hi is not None:
        mine = next((u for u in units if u.tu == name), None)
        if mine is None or mine.hi != hi:
            new_bounds.append(L.Bound(hi, "end", name, by))
            units, l7 = L.compute_units(v.game, new_bounds, srcs, fstarts)
            lines.append((hi, "end"))
    hyp = l7 + all_issues(v, units, new_bounds, srcs)
    seen = {(i.check, i.message) for i in cur}
    new = [i for i in hyp if (i.check, i.message) not in seen]
    mine = next((u for u in units if u.tu == name), None)
    end = mine.hi if mine else (hi or lo + 1)
    table = []
    for a, b, f in v.funcs:
        if lo <= a < end:
            lits = v.first_lits(a)
            table.append({"fn": a, "size": b - a, "fill": (v.fills.get(a) or {}).get("pre"), "drafted": a in v.sources,
                          "lits": len(lits), "first_lit": lits[0].lo if lits else None,
                          "leaks": sorted({l.path for l in v.leaks if l.fn == a})})
    return Proposal(lo, end, name, lines, table, new, cur)
