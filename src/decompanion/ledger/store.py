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
  blob      hash, kind, data                disassembly, include sets, logs, lib sections, Ghidra drafts
  bytemap   lo, hi, cls, level, symbol, unit, source, section   non-overlapping, total over the image
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .fact import Conflict, Fact, Kind, Level, canonical

SCHEMA_VERSION = "1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS input (key TEXT PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run (
    id INTEGER PRIMARY KEY, rule TEXT NOT NULL, version TEXT NOT NULL, code_hash TEXT NOT NULL,
    input_hash TEXT NOT NULL, out_hash TEXT NOT NULL DEFAULT '', current INTEGER NOT NULL DEFAULT 0,
    ms INTEGER NOT NULL DEFAULT 0, at REAL NOT NULL DEFAULT 0, UNIQUE(rule, input_hash));
CREATE TABLE IF NOT EXISTS fact (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, lo INTEGER NOT NULL, hi INTEGER NOT NULL, kind TEXT NOT NULL,
    value TEXT NOT NULL, level INTEGER NOT NULL, by TEXT NOT NULL, reason TEXT);
CREATE INDEX IF NOT EXISTS fact_kind_lo ON fact (kind, lo);
CREATE INDEX IF NOT EXISTS fact_run ON fact (run_id);
CREATE TABLE IF NOT EXISTS conflict (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, severity TEXT NOT NULL, check_id TEXT NOT NULL,
    lo INTEGER NOT NULL, hi INTEGER NOT NULL, message TEXT NOT NULL, a TEXT NOT NULL DEFAULT '', b TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS conflict_run ON conflict (run_id);
CREATE TABLE IF NOT EXISTS blob (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS bytemap (
    lo INTEGER PRIMARY KEY, hi INTEGER NOT NULL, cls TEXT NOT NULL, level INTEGER NOT NULL,
    symbol INTEGER, unit INTEGER, source INTEGER, section INTEGER);
"""


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


@dataclass(frozen=True, slots=True)
class StoredFact:
    id: int
    run: str          # the rule id of the producing run
    fact: Fact

    def __getattr__(self, item):
        return getattr(self.fact, item)


class Store:
    def __init__(self, path: Path, overlay_of: Path | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # uri=True: the overlay ATTACHes main's store read-only through a file: URI (?mode=ro)
        self.db = sqlite3.connect(self.path, isolation_level=None, uri=True)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        v = self.meta("schema")
        if v is None:
            self.set_meta("schema", SCHEMA_VERSION)
        elif v != SCHEMA_VERSION:
            raise RuntimeError(f"{self.path}: store schema {v}, this code wants {SCHEMA_VERSION}: delete build/")
        self.main = None
        if overlay_of is not None and Path(overlay_of).exists():
            self.db.execute("ATTACH DATABASE ? AS main_store", (Path(overlay_of).resolve().as_uri() + "?mode=ro",))
            self.main = Path(overlay_of)

    def close(self):
        self.db.close()

    # ------------------------------------------------------------------ meta / inputs
    def meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str):
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def note_input(self, key: str, hash_: str):
        self.db.execute("INSERT OR REPLACE INTO input (key, hash) VALUES (?, ?)", (key, hash_))

    # ------------------------------------------------------------------ runs
    def current_run(self, rule: str):
        """(id, input_hash, out_hash) of the rule's current run in this store, else None."""
        return self.db.execute("SELECT id, input_hash, out_hash FROM run WHERE rule=? AND current=1", (rule,)).fetchone()

    def find_run(self, rule: str, input_hash: str):
        """A run of this rule with these inputs, in the overlay or the main store: (db, id, out_hash)."""
        row = self.db.execute("SELECT id, out_hash FROM run WHERE rule=? AND input_hash=?", (rule, input_hash)).fetchone()
        if row:
            return ("main", row[0], row[1])
        if self.main is not None:
            row = self.db.execute("SELECT id, out_hash FROM main_store.run WHERE rule=? AND input_hash=?",
                                  (rule, input_hash)).fetchone()
            if row:
                return ("main_store", row[0], row[1])
        return None

    def make_current(self, rule: str, where: str, run_id: int) -> int:
        """Make the run current in this store, copying it from the main store if it lives there. Returns the
        local run id."""
        if where == "main_store":
            run_id = self._copy_run(run_id)
        self.db.execute("UPDATE run SET current=0 WHERE rule=? AND id<>?", (rule, run_id))
        self.db.execute("UPDATE run SET current=1 WHERE id=?", (run_id,))
        return run_id

    def _copy_run(self, main_id: int) -> int:
        r = self.db.execute("SELECT rule, version, code_hash, input_hash, out_hash, ms, at FROM main_store.run WHERE id=?",
                            (main_id,)).fetchone()
        cur = self.db.execute("INSERT INTO run (rule, version, code_hash, input_hash, out_hash, ms, at) VALUES (?,?,?,?,?,?,?)", r)
        new_id = cur.lastrowid
        self.db.execute("INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) "
                        "SELECT ?, lo, hi, kind, value, level, by, reason FROM main_store.fact WHERE run_id=?", (new_id, main_id))
        self.db.execute("INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) "
                        "SELECT ?, severity, check_id, lo, hi, message, a, b FROM main_store.conflict WHERE run_id=?", (new_id, main_id))
        return new_id

    def record_run(self, rule: str, version: str, code_hash: str, input_hash: str,
                   facts: list[Fact], conflicts: list[Conflict], ms: int) -> int:
        """Store a finished run with its output, make it current, drop the facts of the rule's older runs
        (only the latest run of a rule is kept: the store is a cache, not a history)."""
        facts = sorted(facts, key=Fact.key)
        conflicts = sorted(conflicts, key=lambda c: (c.lo, c.hi, c.check, c.message))
        out_hash = sha256(*(canonical(f.key() + (int(f.level), f.by, f.reason or "")) for f in facts),
                          *(canonical((c.lo, c.hi, c.check, c.severity.value, c.message)) for c in conflicts))
        self.db.execute("BEGIN")
        try:
            old = [r[0] for r in self.db.execute("SELECT id FROM run WHERE rule=?", (rule,)).fetchall()]
            for oid in old:
                self.db.execute("DELETE FROM fact WHERE run_id=?", (oid,))
                self.db.execute("DELETE FROM conflict WHERE run_id=?", (oid,))
                self.db.execute("DELETE FROM run WHERE id=?", (oid,))
            cur = self.db.execute(
                "INSERT INTO run (rule, version, code_hash, input_hash, out_hash, current, ms, at) VALUES (?,?,?,?,?,1,?,?)",
                (rule, version, code_hash, input_hash, out_hash, ms, time.time()))
            run_id = cur.lastrowid
            self.db.executemany(
                "INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) VALUES (?,?,?,?,?,?,?,?)",
                [(run_id, f.lo, f.hi, f.kind.value, canonical(f.value), int(f.level), f.by, f.reason) for f in facts])
            self.db.executemany(
                "INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) VALUES (?,?,?,?,?,?,?,?)",
                [(run_id, c.severity.value, c.check, c.lo, c.hi, c.message, c.a, c.b) for c in conflicts])
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return run_id

    def runs(self):
        """[(rule, version, input_hash, out_hash, current, ms, at)] of every run in this store."""
        return self.db.execute("SELECT rule, version, input_hash, out_hash, current, ms, at FROM run ORDER BY rule").fetchall()

    # ------------------------------------------------------------------ facts
    @staticmethod
    def _row_fact(row) -> StoredFact:
        fid, rule, lo, hi, kind, value, level, by, reason = row
        return StoredFact(fid, rule, Fact(lo, hi, Kind(kind), json.loads(value), Level(level), by, reason))

    def facts(self, kind: Kind | str | None = None, lo: int | None = None, hi: int | None = None,
              rules: tuple[str, ...] | None = None) -> list[StoredFact]:
        """Facts of current runs, optionally of one kind, intersecting [lo, hi), produced by the given rules.
        Sorted by (lo, hi, kind, value)."""
        q = ("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f "
             "JOIN run r ON r.id = f.run_id WHERE r.current=1")
        args: list = []
        if kind is not None:
            q += " AND f.kind=?"
            args.append(Kind(kind).value)
        if lo is not None:
            q += " AND f.hi>?"
            args.append(lo)
        if hi is not None:
            q += " AND f.lo<?"
            args.append(hi)
        if rules:
            q += " AND r.rule IN (%s)" % ",".join("?" * len(rules))
            args.extend(rules)
        q += " ORDER BY f.lo, f.hi, f.kind, f.value"
        return [self._row_fact(r) for r in self.db.execute(q, args)]

    def fact(self, fid: int) -> StoredFact | None:
        row = self.db.execute("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f "
                              "JOIN run r ON r.id=f.run_id WHERE f.id=?", (fid,)).fetchone()
        return self._row_fact(row) if row else None

    def conflicts(self, severity: str | None = None) -> list[Conflict]:
        q = ("SELECT c.severity, c.check_id, c.lo, c.hi, c.message, c.a, c.b FROM conflict c JOIN run r ON r.id=c.run_id "
             "WHERE r.current=1")
        args = []
        if severity:
            q += " AND c.severity=?"
            args.append(severity)
        q += " ORDER BY c.lo, c.hi, c.check_id, c.message"
        return [Conflict(*r) for r in self.db.execute(q, args)]

    # ------------------------------------------------------------------ blobs
    def blob(self, hash_: str) -> bytes | None:
        row = self.db.execute("SELECT data FROM blob WHERE hash=?", (hash_,)).fetchone()
        if row is None and self.main is not None:
            row = self.db.execute("SELECT data FROM main_store.blob WHERE hash=?", (hash_,)).fetchone()
        return bytes(row[0]) if row else None

    def put_blob(self, hash_: str, kind: str, data: bytes, replace: bool = False):
        """Store a blob. Content-addressed blobs never change (INSERT OR IGNORE); a blob keyed by something else
        (a Ghidra draft keyed by image and start) is replaced when `replace`."""
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        self.db.execute(f"{verb} INTO blob (hash, kind, data) VALUES (?, ?, ?)", (hash_, kind, data))

    def blobs(self, kind: str) -> dict[str, bytes]:
        """Every blob of one kind, main store first, the overlay's own replacing it: {hash: data}."""
        out = {}
        if self.main is not None:
            out.update((h, bytes(d)) for h, d in self.db.execute("SELECT hash, data FROM main_store.blob WHERE kind=?", (kind,)))
        out.update((h, bytes(d)) for h, d in self.db.execute("SELECT hash, data FROM blob WHERE kind=?", (kind,)))
        return out

    def main_meta(self, key: str) -> str | None:
        """A meta value of the main store (None outside a worktree)."""
        if self.main is None:
            return None
        row = self.db.execute("SELECT value FROM main_store.meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def blob_json(self, hash_: str):
        b = self.blob(hash_)
        return None if b is None else json.loads(b.decode())

    def put_blob_json(self, hash_: str, kind: str, value):
        self.put_blob(hash_, kind, canonical(value).encode())

    # ------------------------------------------------------------------ bytemap
    def write_bytemap(self, rows: list[tuple], hash_: str):
        self.db.execute("BEGIN")
        self.db.execute("DELETE FROM bytemap")
        self.db.executemany("INSERT INTO bytemap (lo, hi, cls, level, symbol, unit, source, section) VALUES (?,?,?,?,?,?,?,?)", rows)
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('bytemap', ?)", (hash_,))
        self.db.execute("COMMIT")

    def bytemap_at(self, addr: int):
        return self.db.execute("SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap WHERE lo<=? "
                               "ORDER BY lo DESC LIMIT 1", (addr,)).fetchone()

    def bytemap_rows(self, lo: int | None = None, hi: int | None = None):
        q, args = "SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap", []
        if lo is not None or hi is not None:
            q += " WHERE 1=1"
            if lo is not None:
                q += " AND hi>?"
                args.append(lo)
            if hi is not None:
                q += " AND lo<?"
                args.append(hi)
        return self.db.execute(q + " ORDER BY lo", args).fetchall()
