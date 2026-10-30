"""Queries over the store: the materialised byte map, `why`, summaries. Every answer is computed from current
facts; the byte map is rebuilt when the facts it is made of changed (hash in meta)."""
from __future__ import annotations

from collections import Counter, defaultdict

from .fact import Kind, Level, canonical
from .store import Store, sha256

MAP_KINDS = (Kind.section, Kind.region, Kind.symbol, Kind.unit, Kind.source)


def _cls(f) -> str:
    v = f.value
    if f.kind is Kind.region:
        return "region." + v["what"]
    if f.kind is Kind.symbol:
        return v["skind"]
    return f.kind.value


_maps: dict[tuple, bool] = {}       # (store, run id, at) -> the run has facts of a kind the byte map is made of


def ensure_bytemap(store: Store) -> str:
    """Rebuild the byte map when the symbol / region / section / unit / source facts changed. Returns the hash: of
    the current runs (id and time) that hold such facts; the map rows name fact ids, so a run recorded again
    changes it although its output is the same."""
    runs = store.db.execute("SELECT rule, id, at FROM run WHERE current=1 ORDER BY rule").fetchall()
    kinds = [k.value for k in MAP_KINDS]
    parts = []
    for rule, rid, at in runs:
        k = (str(store.path), rid, at)
        has = _maps.get(k)
        if has is None:
            has = _maps[k] = store.db.execute(
                f"SELECT 1 FROM fact WHERE run_id=? AND kind IN ({','.join('?' * len(kinds))}) LIMIT 1",
                (rid, *kinds)).fetchone() is not None
        if has:
            parts.append(f"{rule}={rid}@{at!r}")
    h = sha256("bytemap.v2", *parts)
    if store.meta("bytemap") == h:
        return h
    symbols = store.facts(Kind.symbol) + store.facts(Kind.region)
    sections = store.facts(Kind.section)
    units = store.facts(Kind.unit)
    sources = store.facts(Kind.source)
    cuts = set()
    for group in (symbols, sections, units, sources):
        for f in group:
            cuts.add(f.lo)
            cuts.add(f.hi)
    cuts = sorted(cuts)
    rows = []

    class Sweep:
        """The fact of one group that owns each cut, cuts visited in address order: among the facts covering
        the address the highest level, then the highest lo, then the highest hi."""

        def __init__(self, facts):
            self.items = sorted(((f.fact.lo, f.fact.hi, int(f.fact.level), f) for f in facts), key=lambda t: (t[0], t[1]))
            self.i = 0
            self.active = []

        def at(self, a):
            items, active = self.items, self.active
            while self.i < len(items) and items[self.i][0] <= a:
                active.append(items[self.i])
                self.i += 1
            if active:
                active[:] = [t for t in active if t[1] > a]
            if not active:
                return None
            return max(reversed(active), key=lambda t: (t[2], t[0], t[1]))[3]      # equal keys: the later fact

    isym, isec, iunit, isrc = Sweep(symbols), Sweep(sections), Sweep(units), Sweep(sources)
    for a, b in zip(cuts, cuts[1:]):
        s, sec, u, src = isym.at(a), isec.at(a), iunit.at(a), isrc.at(a)
        if s is None:
            continue
        rows.append((a, b, _cls(s), int(s.level), s.id, u.id if u else None, src.id if src else None, sec.id if sec else None))
    store.write_bytemap(rows, h)
    return h


def why(store: Store, addr: int) -> dict:
    """Everything known about one address: the byte map row, every fact that covers it, references to and
    from it."""
    ensure_bytemap(store)
    row = store.bytemap_at(addr)
    out = {"addr": addr, "row": row, "facts": store.facts(None, addr, addr + 1), "refs_to": [], "refs_from": []}
    sym = store.fact(row[4]) if row else None
    if sym is not None:
        lo, hi = sym.lo, sym.hi
        out["refs_to"] = [f for f in store.facts(Kind.ref) if lo <= f.value.get("to", -1) < hi]
        out["refs_from"] = [f for f in store.facts(Kind.ref, lo, hi)]
        out["symbol"] = sym
    return out


def summary(store: Store) -> dict:
    """Bytes per section per class and level."""
    ensure_bytemap(store)
    by_sec = defaultdict(lambda: defaultdict(int))
    by_level = defaultdict(lambda: defaultdict(int))
    secs = {f.id: f for f in store.facts(Kind.section)}
    for lo, hi, cls, level, sym, unit, src, sec in store.bytemap_rows():
        name = secs[sec].value["name"] if sec in secs else "(headers)"
        by_sec[name][cls] += hi - lo
        by_level[name][Level(level).name] += hi - lo
    return {"by_section": by_sec, "by_level": by_level}
