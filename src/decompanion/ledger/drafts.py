"""Drafts: what the configured analyzer (analyzers/) said about a target's functions, kept in the target's store.

`dcp setup` runs the analyzer's export (build/analyzer.py) and replaces the store's drafts with its entries:
one blob of kind `drafts` per function, keyed by (image sha256, function entry), its value the entry with the
analyzer's key, so a worktree reads main's drafts through its overlay. The meta key `drafts` is the hash over
the stored entries: the input hash of the loader rule L.analyzer, which turns every entry into a `start` fact
(how = the analyzer's key, level declared, reason "<key> analysis": an external tool's claim is a declaration,
never a computed fact), and of L9. The meta key `drafts.export` holds the export key (analyzer, image, script,
our starts): the same key again means nothing to do.
"""
from __future__ import annotations

import json

from ..analyzers.base import Entry
from .store import Store, canonical, sha256

KIND = "drafts"
EXPORT = "drafts.export"


def key(image_sha: str, start: int) -> str:
    return sha256(KIND, image_sha, f"{start:08x}")


def _value(e: Entry) -> dict:
    v = {"start": e.start, "name": e.name, "requested": e.requested if e.requested is not None else e.start, "source": e.source,
         "body": e.body, "analyzer": e.analyzer}
    if e.end is not None:
        v.update(end=e.end, size=e.size, ranges=[list(r) for r in e.ranges])
    if e.seeded:
        v["seeded"] = True
    return v


def replace(store: Store, image_sha: str, entries: list[Entry]) -> int:
    """Make these entries the store's drafts (every older draft of this store goes) and set meta `drafts`."""
    store.drop_blobs(KIND)
    by_start = {e.start: e for e in entries}
    h = ""
    for a in sorted(by_start):
        k = key(image_sha, a)
        data = canonical(_value(by_start[a]))
        store.put_blob(k, KIND, data.encode(), replace=True)
        h = sha256(h, k, data)
    store.set_meta(KIND, h)
    return len(by_start)


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


def draft(store: Store, image_sha: str, start: int) -> Entry | None:
    b = store.blob(key(image_sha, start))
    if b is None:
        return None
    return _entry(json.loads(b.decode()))


def input_hash(store: Store) -> str:
    return sha256(store.main_meta(KIND) or "", store.meta(KIND) or "")
