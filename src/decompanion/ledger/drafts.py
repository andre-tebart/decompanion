"""Drafts: what the configured analyzer said about a target's functions, kept in the target's store.

`dcp setup` runs the analyzer's export (the core's analyzers.rs) and replaces the store's drafts with its entries:
one blob of kind `drafts` per function, keyed by (image sha256, function entry), its value the entry with the
analyzer's key, so a worktree reads main's drafts through its overlay. The meta key `drafts` is the hash over
the stored entries: the input hash of the loader rule L.analyzer, which turns every entry into a `start` fact
(how = the analyzer's key, level declared, reason "<key> analysis": an external tool's claim is a declaration,
never a computed fact), and of L9. The meta key `drafts.export` holds the export key (analyzer, image, script,
our starts): the same key again means nothing to do.
"""
from __future__ import annotations

import json

from dataclasses import dataclass

from .store import Store


@dataclass(frozen=True)
class Entry:
    """One function as an analyzer sees it."""
    start: int                    # the function's entry
    name: str                     # the tool's name for it ('' when none)
    body: str                     # the pseudocode ('' when the tool gave none)
    end: int | None = None        # the end of its highest address range (exclusive), when the tool reports ranges
    size: int | None = None       # bytes in its ranges
    ranges: tuple = ()            # ((lo, hi), ...)
    seeded: bool = False          # made by the tool at one of our starts on our request: no claim of the tool's
    requested: int | None = None  # the address it was asked for (None: its start)
    source: str = ""              # the file the entry came from (its name)
    analyzer: str = ""            # the plugin key


KIND = "drafts"


def _entry(v: dict) -> Entry:
    return Entry(v["start"], v.get("name", ""), v["body"], v.get("end"), v.get("size"), tuple(tuple(r) for r in v.get("ranges") or ()),
                 bool(v.get("seeded")), v.get("requested", v["start"]), v.get("source", ""), v.get("analyzer", ""))


def entries(store: Store) -> list[Entry]:
    """Every draft (main's and the overlay's), sorted by start."""
    out = {}
    for _, data in store.blobs(KIND).items():
        v = json.loads(data.decode())
        out[v["start"]] = _entry(v)
    return [out[k] for k in sorted(out)]
