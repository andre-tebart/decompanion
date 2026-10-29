"""Queries over the store: the materialised byte map, `why`, summaries. Every answer is computed from current
facts; the byte map is rebuilt when the facts it is made of changed (hash in meta)."""
from __future__ import annotations

import bisect
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


def ensure_bytemap(store: Store) -> str:
    """Rebuild the byte map when the symbol / region / section / unit / source facts changed. Returns the hash."""
    runs = store.db.execute("SELECT rule, out_hash FROM run WHERE current=1 ORDER BY rule").fetchall()
    h = sha256(*(f"{r}={o}" for r, o in runs))
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

    def index(facts):
        facts = sorted(facts, key=lambda f: (f.lo, -f.level, f.hi))
        los = [f.lo for f in facts]
        return facts, los

    def lookup(idx, a):
        facts, los = idx
        i = bisect.bisect_right(los, a) - 1
        best = None
        while i >= 0 and facts[i].lo <= a:
            f = facts[i]
            if f.lo <= a < f.hi and (best is None or f.level > best.level):
                best = f
            i -= 1
            if i >= 0 and facts[i].hi <= a and facts[i].lo < a - 0x100000:
                break
        return best

    isym, isec, iunit, isrc = index(symbols), index(sections), index(units), index(sources)
    for a, b in zip(cuts, cuts[1:]):
        s = lookup(isym, a)
        if s is None:
            continue
        sec = lookup(isec, a)
        u = lookup(iunit, a)
        src = lookup(isrc, a)
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
