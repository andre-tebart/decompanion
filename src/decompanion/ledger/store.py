"""The derived-state store: one SQLite file per target (build/<target>.sqlite) holding every rule run, its facts
and conflicts, content-addressed blobs, and the materialised byte map. Facts carry no target column: each
target's address space has a store of its own.

Nothing in the store is typed state: it is a cache of what the rules computed from the image, the sources, the
declarations and the toolchain, and it can be deleted at any time (the next command recomputes). Every rule run
is keyed by the hash of its inputs (the core's engine.rs), so a run whose inputs did not change is never repeated,
and a worktree can read the main checkout's store through an overlay (attach): lookups go overlay first, then main.

The store is the core's (native/dcp_core/src/store.rs, pystore.rs: the schema, the connection, the queries, the
byte map); this module is the face the commands and the tests read it through. Facts come back as the core's
StoredFact objects (lo, hi, kind, value, level, by, reason, the row id and the producing rule).
"""
from __future__ import annotations

import os
from pathlib import Path

from .. import native
from .fact import Conflict

_core = native.core()

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

    def facts(self, kind=None, lo: int | None = None, hi: int | None = None, rules: tuple[str, ...] | None = None):
        """Facts of current runs, optionally of one kind, intersecting [lo, hi), produced by the given rules.
        Sorted by (lo, hi, kind, value)."""
        return _core.st_facts(self._p, None if kind is None else str(kind), lo, hi, list(rules) if rules else None)

    def fact(self, fid: int):
        return _core.st_fact(self._p, fid)

    def conflicts(self, severity: str | None = None, rules: tuple[str, ...] | None = None) -> list[Conflict]:
        """Conflicts of current runs (of the given rules), sorted by address."""
        return [Conflict(*r) for r in _core.st_conflicts(self._p, severity, list(rules) if rules else None)]

    def ensure_bytemap(self) -> str:
        """Rebuild the byte map when the facts it is made of changed; its hash."""
        return _core.st_ensure_bytemap(self._p)

    def bytemap_rows(self, lo: int | None = None, hi: int | None = None):
        """The byte map rows intersecting [lo, hi) (the map built first when its facts changed)."""
        return _core.st_bytemap_rows(self._p, lo, hi)

    def bytemap_at(self, addr: int):
        """The byte map row holding addr (the map built first when its facts changed)."""
        return _core.st_bytemap_at(self._p, addr)

    def blobs(self, kind: str) -> dict[str, bytes]:
        """Every blob of one kind, main store first, the overlay's own replacing it: {hash: data}."""
        return _core.st_blobs(self._p, self._main, kind)
