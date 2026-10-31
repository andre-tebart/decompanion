"""The derived-state store: one SQLite file per target (build/<target>.sqlite) holding every rule run, its facts
and conflicts, content-addressed blobs, and the materialised byte map. Facts carry no target column: each
target's address space has a store of its own.

Nothing in the store is typed state: it is a cache of what the rules computed from the image, the sources, the
declarations and the toolchain, and it can be deleted at any time (the next command recomputes). Every rule run
is keyed by the hash of its inputs (store.engine), so a run whose inputs did not change is never repeated, and
a worktree can read the main checkout's store through an overlay (attach): lookups go overlay first, then main.

Tables
  meta      key, value                      schema version, image hash, bytemap hash
  input     key, hash                       the last seen content hash of each named input (for `dcp rules`)
  run       rule, version, code_hash, input_hash, out_hash, current, ms, at
  fact      run_id, lo, hi, kind, value, level, by, reason      (only facts of current runs are visible)
  conflict  run_id, severity, check, lo, hi, message, a, b
  blob      hash, kind, data                disassembly, include sets, logs, lib sections, drafts
  bytemap   lo, hi, cls, level, symbol, unit, source, section   non-overlapping, total over the image
  tu        unit, amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags, at
            one row per translation unit of the target (build/compile.py): the hashes of the last compile's
            inputs, the object it produced (build/obj/<obj_hash>.obj; '' when it failed), its log and diagnostics
  include_set  key, files                   the include set of a unit per (source hash, flags hash, listing hash)
The tu and include_set tables were added in milestone 3 (CREATE IF NOT EXISTS: older stores gain them).

The store is the core's (native/dcp_core/src/pystore.rs: the connection, the queries, the byte map); this module is
its face. Facts come back as the core's StoredFact objects (Fact's fields, the row id and the producing rule).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .. import native
from .fact import Conflict, Fact

_core = native.core()
SCHEMA_VERSION, SCHEMA = _core.store_schema()         # the tables: the core's (store.rs)
StoredFact = _core.StoredFact


def sha256(*parts: bytes | str) -> str:
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, str):
            p = p.encode()
        h.update(p)
        h.update(b"\0")
    return h.hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_open: dict[tuple, tuple] = {}
KEEP_OPEN = False         # dcp serve: a store stays open across requests


def _ident(path, overlay_of):
    try:
        return (os.stat(path).st_ino, os.stat(overlay_of).st_ino if overlay_of and Path(overlay_of).exists() else 0)
    except OSError:
        return None


class Store:
    @classmethod
    def open(cls, path: Path, overlay_of: Path | None = None) -> Store:
        """The store at path: this process's one as long as it is the same file (deleted and recreated: the core's
        connection to it is closed and opened again)."""
        key = (str(Path(path).resolve()).lower(), str(overlay_of or ""))
        hit = _open.get(key) if KEEP_OPEN else None
        ident = _ident(path, overlay_of)
        if hit is not None and ident is not None and hit[0] == ident:
            return hit[1]
        _core.st_close(str(path))
        st = cls(path, overlay_of)
        if KEEP_OPEN:
            _open[key] = (_ident(path, overlay_of), st)
        return st

    def __init__(self, path: Path, overlay_of: Path | None = None):
        self.path = Path(path)
        self._p = str(self.path)
        self.main = Path(overlay_of) if overlay_of is not None and Path(overlay_of).exists() else None
        self._main = self.main.resolve().as_uri() + "?mode=ro" if self.main is not None else ""
        _core.st_open(self._p, self._main)

    def close(self):
        _core.st_close(self._p)

    # ------------------------------------------------------------------ meta / inputs
    def meta(self, key: str) -> str | None:
        return _core.st_meta(self._p, key)

    def meta_json(self, key: str):
        """A meta value that holds JSON, as Python objects (None when there is none)."""
        return _core.st_meta_json(self._p, key)

    def set_meta(self, key: str, value: str):
        _core.st_set_meta(self._p, key, value)

    def main_meta(self, key: str) -> str | None:
        """A meta value of the main store (None outside a worktree)."""
        return _core.st_main_meta(self._p, self._main, key)

    def note_input(self, key: str, hash_: str):
        _core.st_note_input(self._p, key, hash_)

    # ------------------------------------------------------------------ runs
    def current_run(self, rule: str):
        """(id, input_hash, out_hash) of the rule's current run in this store, else None."""
        return _core.st_current_run(self._p, rule)

    def find_run(self, rule: str, input_hash: str):
        """A run of this rule with these inputs, in the overlay or the main store: (where, id, out_hash)."""
        return _core.st_find_run(self._p, self._main, rule, input_hash)

    def make_current(self, rule: str, where: str, run_id: int) -> int:
        """Make the run current in this store, copying it from the main store if it lives there. Returns the
        local run id."""
        return _core.st_make_current(self._p, self._main, rule, where, run_id)

    def record_run(self, rule: str, version: str, code_hash: str, input_hash: str,
                   facts: list[Fact], conflicts: list[Conflict], ms: int) -> int:
        """Store a finished run with its output and make it current (the core's record_run: only the latest run of
        a rule is kept; an output equal to the current run's keeps its fact rows)."""
        run_id, _ = _core.record_run(self._p, rule, version, code_hash, input_hash, list(facts), list(conflicts), ms,
                                     not os.environ.get("DCP_NO_SHORTCUTS"))
        return run_id

    def runs(self):
        """[(rule, version, input_hash, out_hash, current, ms, at)] of every run in this store."""
        return _core.st_runs(self._p)

    def run_stats(self, run_id: int) -> tuple[int, int]:
        """(facts, ms) of a run."""
        return _core.st_run_stats(self._p, run_id)

    # ------------------------------------------------------------------ facts
    def facts(self, kind=None, lo: int | None = None, hi: int | None = None, rules: tuple[str, ...] | None = None):
        """Facts of current runs, optionally of one kind, intersecting [lo, hi), produced by the given rules.
        Sorted by (lo, hi, kind, value)."""
        return _core.st_facts(self._p, None if kind is None else str(kind), lo, hi, list(rules) if rules else None)

    def fact(self, fid: int):
        return _core.st_fact(self._p, fid)

    def conflicts(self, severity: str | None = None, rules: tuple[str, ...] | None = None) -> list[Conflict]:
        """Conflicts of current runs (of the given rules), sorted by address."""
        return [Conflict(*r) for r in _core.st_conflicts(self._p, severity, list(rules) if rules else None)]

    # ------------------------------------------------------------------ blobs
    def blob(self, hash_: str) -> bytes | None:
        return _core.st_blob(self._p, self._main, hash_)

    def put_blob(self, hash_: str, kind: str, data: bytes, replace: bool = False):
        """Store a blob. Content-addressed blobs never change; a blob keyed by something else (an analyzer's draft
        keyed by image and start) is replaced when `replace`."""
        _core.st_put_blob(self._p, hash_, kind, bytes(data), replace)

    def drop_blobs(self, kind: str):
        """Delete every blob of one kind from this store (never from the main store under an overlay)."""
        _core.st_drop_blobs(self._p, kind)

    def blobs(self, kind: str) -> dict[str, bytes]:
        """Every blob of one kind, main store first, the overlay's own replacing it: {hash: data}."""
        return _core.st_blobs(self._p, self._main, kind)

    def blob_json(self, hash_: str):
        return _core.st_blob_json(self._p, self._main, hash_)

    def put_blob_json(self, hash_: str, kind: str, value):
        _core.st_put_blob_json(self._p, hash_, kind, value)

    # ------------------------------------------------------------------ translation units
    def tus(self) -> dict[str, dict]:
        """unit -> its tu row (flags and diags decoded)."""
        return _core.st_tus(self._p)

    def tu_keys(self) -> dict[str, dict]:
        """unit -> its tu row's keys and outcome only (no log, flags or diagnostics)."""
        return _core.st_tu_keys(self._p)

    def put_tu(self, row: dict):
        _core.st_put_tu(self._p, row)

    def drop_tu(self, unit: str):
        _core.st_drop_tu(self._p, unit)

    def tu_hash(self) -> str:
        """The hash of every tu row's inputs and outcome: the `objects` input of the match rules."""
        return _core.st_tu_hash(self._p)

    def include_set(self, key: str) -> list[str] | None:
        return _core.st_include_set(self._p, key)

    def put_include_set(self, key: str, files: list[str]):
        _core.st_put_include_set(self._p, key, list(files))

    # ------------------------------------------------------------------ bytemap
    def ensure_bytemap(self) -> str:
        """Rebuild the byte map when the facts it is made of changed; its hash."""
        return _core.st_ensure_bytemap(self._p)

    def bytemap_at(self, addr: int):
        """The byte map row holding addr (the map built first when its facts changed)."""
        return _core.st_bytemap_at(self._p, addr)

    def bytemap_rows(self, lo: int | None = None, hi: int | None = None):
        """The byte map rows intersecting [lo, hi) (the map built first when its facts changed)."""
        return _core.st_bytemap_rows(self._p, lo, hi)

    def summary(self) -> dict:
        """Bytes per section per class and level."""
        by_section, by_level = _core.st_summary(self._p)
        return {"by_section": by_section, "by_level": by_level}
