"""Queries over the store: `why`, summaries. Every answer is computed from current facts; the byte map is the
core's (pystore.rs), rebuilt when the facts it is made of changed (hash in meta)."""
from __future__ import annotations

from .fact import Kind
from .store import Store


def why(store: Store, addr: int) -> dict:
    """Everything known about one address: the byte map row, every fact that covers it, references to and
    from it."""
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
    """Bytes per section per class and level (the core's: pystore.rs st_summary)."""
    return store.summary()
