"""Ghidra drafts: Ghidra's decompilation of a target's functions, imported into the target's store.

Two producers write the same JSON shape: `dcp ghidra export` (Ghidra headless with the shipped script
data/ghidra/DcpExport.java, build/ghidra.py) and a saved REA `batch_decompile` result (`dcp ghidra import`).
It holds `subject.digest.sha256` (the analysed binary) and `normalized_result.items`: per requested address its
`status`, the `procedure` Ghidra resolved (`address` = the function's entry, `name`), the `pseudocode`, and
(the export only) the function's `body`: start, end (exclusive), size in bytes, address ranges. Each ok item
becomes one blob of
kind `ghidra`, keyed by (image sha256, function entry), so a re-import replaces the old text and a worktree
reads main's drafts through its overlay. The store's meta key `ghidra` is a running hash over the imports:
it is the input hash of the loader rule L.ghidra, which turns every entry into a `start` fact
(how=ghidra, level declared, reason "ghidra analysis": an external tool's claim is a declaration, never a
computed fact).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .store import Store, canonical, sha256

KIND = "ghidra"


@dataclass(frozen=True)
class Entry:
    start: int
    name: str
    requested: int
    source: str        # the JSON file it came from (its name)
    text: str
    end: int | None = None        # Ghidra's function body: the end of its highest range (exclusive)
    size: int | None = None       # bytes in the body
    ranges: tuple = ()            # ((lo, hi), ...) of the body
    seeded: bool = False          # Ghidra made the function at one of our starts (`dcp ghidra export`): no claim of Ghidra's


def key(image_sha: str, start: int) -> str:
    return sha256(KIND, image_sha, f"{start:08x}")


def parse(path: Path) -> tuple[str, list[Entry], list[str]]:
    """(the analysed binary's sha256 or '', the ok entries, one message per item that failed)."""
    d = json.loads(Path(path).read_text())
    digest = ((d.get("subject") or {}).get("digest") or {}).get("sha256", "")
    items = ((d.get("normalized_result") or {}).get("items")) or []
    out, failed = [], []
    for it in items:
        if it.get("status") != "ok" or "pseudocode" not in it:
            failed.append(f"{it.get('address')}: {it.get('status')} {it.get('error', '')}".strip())
            continue
        req = int(it["address"], 16)
        proc = it.get("procedure") or {}
        start = int(proc["address"], 16) if proc.get("address") else req
        text = it["pseudocode"].replace("\r\n", "\n").strip("\n") + "\n"
        body = it.get("body") or {}
        ranges = tuple((int(a, 16), int(b, 16)) for a, b in body.get("ranges") or ())
        end = int(body["end"], 16) if body.get("end") else None
        out.append(Entry(start, proc.get("name", ""), req, Path(path).name, text, end, body.get("size"), ranges, bool(it.get("seeded"))))
    return digest, out, failed


def store_entries(store: Store, image_sha: str, entries: list[Entry]) -> int:
    """Put the entries into the store (replacing older drafts of the same start) and advance meta `ghidra`."""
    h = store.meta(KIND) or ""
    for e in entries:
        k = key(image_sha, e.start)
        v = {"start": e.start, "name": e.name, "requested": e.requested, "source": e.source, "text": e.text}
        if e.end is not None:
            v.update(end=e.end, size=e.size, ranges=[list(r) for r in e.ranges])
        if e.seeded:
            v["seeded"] = True
        data = canonical(v)
        store.put_blob(k, KIND, data.encode(), replace=True)
        h = sha256(h, k, data)
    store.set_meta(KIND, h)
    return len(entries)


def _entry(v: dict) -> Entry:
    return Entry(v["start"], v.get("name", ""), v.get("requested", v["start"]), v.get("source", ""), v["text"], v.get("end"),
                 v.get("size"), tuple(tuple(r) for r in v.get("ranges") or ()), bool(v.get("seeded")))


def entries(store: Store) -> list[Entry]:
    """Every imported draft (main's and the overlay's), sorted by start."""
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
