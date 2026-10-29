"""Ghidra drafts: saved REA `batch_decompile` results imported into the target's store.

The JSON of one batch_decompile call (as REA returns it, saved to a file) holds `subject.digest.sha256` (the
analysed binary) and `normalized_result.items`: per requested address its `status`, the `procedure` Ghidra
resolved (`address` = the function's entry, `name`) and the `pseudocode`. Each ok item becomes one blob of
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
        out.append(Entry(start, proc.get("name", ""), req, Path(path).name, text))
    return digest, out, failed


def store_entries(store: Store, image_sha: str, entries: list[Entry]) -> int:
    """Put the entries into the store (replacing older drafts of the same start) and advance meta `ghidra`."""
    h = store.meta(KIND) or ""
    for e in entries:
        k = key(image_sha, e.start)
        data = canonical({"start": e.start, "name": e.name, "requested": e.requested, "source": e.source, "text": e.text})
        store.put_blob(k, KIND, data.encode(), replace=True)
        h = sha256(h, k, data)
    store.set_meta(KIND, h)
    return len(entries)


def entries(store: Store) -> list[Entry]:
    """Every imported draft (main's and the overlay's), sorted by start."""
    out = {}
    for _, data in store.blobs(KIND).items():
        v = json.loads(data.decode())
        out[v["start"]] = Entry(v["start"], v.get("name", ""), v.get("requested", v["start"]), v.get("source", ""), v["text"])
    return [out[k] for k in sorted(out)]


def draft(store: Store, image_sha: str, start: int) -> Entry | None:
    b = store.blob(key(image_sha, start))
    if b is None:
        return None
    v = json.loads(b.decode())
    return Entry(v["start"], v.get("name", ""), v.get("requested", v["start"]), v.get("source", ""), v["text"])
