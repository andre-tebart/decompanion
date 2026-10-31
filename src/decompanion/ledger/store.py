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
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import timing
from .fact import Conflict, Fact, Kind, Level, canonical

from .. import native

SCHEMA_VERSION, SCHEMA = native.core().store_schema()         # the tables: the core's (store.rs)


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
    # the fact's fields, copied: the rules read them millions of times per refresh, a slot is a plain lookup where
    # __getattr__ (still there for the rest of Fact) is a Python call
    lo: int = field(init=False, compare=False, repr=False)
    hi: int = field(init=False, compare=False, repr=False)
    kind: Kind = field(init=False, compare=False, repr=False)
    value: dict = field(init=False, compare=False, repr=False)
    level: Level = field(init=False, compare=False, repr=False)
    by: str = field(init=False, compare=False, repr=False)
    reason: str | None = field(init=False, compare=False, repr=False)

    def __post_init__(self):
        f, s = self.fact, object.__setattr__
        s(self, "lo", f.lo)
        s(self, "hi", f.hi)
        s(self, "kind", f.kind)
        s(self, "value", f.value)
        s(self, "level", f.level)
        s(self, "by", f.by)
        s(self, "reason", f.reason)

    def __getattr__(self, item):
        return getattr(self.fact, item)


_open: dict[tuple, tuple] = {}
KEEP_OPEN = False         # dcp serve: a store stays open across requests (its decoded-facts memo with it)


class Store:
    @classmethod
    def open(cls, path: Path, overlay_of: Path | None = None) -> Store:
        """The store at path: a new connection, or (KEEP_OPEN) the one this process opened before, as long as it is
        the same file (deleted and recreated: a new connection)."""
        if not KEEP_OPEN:
            return cls(path, overlay_of)
        key = (str(Path(path).resolve()).lower(), str(overlay_of or ""))
        try:
            ident = (os.stat(path).st_ino, os.stat(overlay_of).st_ino if overlay_of and Path(overlay_of).exists() else 0)
        except OSError:
            ident = None
        hit = _open.get(key)
        if hit is not None and ident is not None and hit[0] == ident:
            return hit[1]
        if hit is not None:
            hit[1].close()
        st = cls(path, overlay_of)
        ident = (os.stat(path).st_ino, os.stat(overlay_of).st_ino if overlay_of and Path(overlay_of).exists() else 0)
        _open[key] = (ident, st)
        return st

    def __init__(self, path: Path, overlay_of: Path | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # uri=True: the overlay ATTACHes main's store read-only through a file: URI (?mode=ro)
        self.db = sqlite3.connect(self.path, isolation_level=None, uri=True)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        try:
            v = self.meta("schema")
        except sqlite3.OperationalError:          # a new store: no meta table yet
            v = None
        if v != SCHEMA_VERSION:
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
        (only the latest run of a rule is kept: the store is a cache, not a history). When the output equals the
        current run's (out_hash), the run row takes the new key and its facts stay as they are, ids and all
        (the conflicts are written again: out_hash does not cover their a / b). Written by the native core
        (dcp_core record_run) on its own connection: the same SQL and out_hash Python's version wrote (proven by
        a shadow run on gildegold before it was deleted, docs/plan.md section 20)."""
        from .. import native
        run_id, _ = native.core().record_run(str(self.path), rule, version, code_hash, input_hash, list(facts),
                                             list(conflicts), ms, not os.environ.get("DCP_NO_SHORTCUTS"))
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
        Sorted by (lo, hi, kind, value). A whole-store read (no range) decodes each run's facts of a kind once per
        process: a run's facts never change after it is recorded, so the run id keys them."""
        if lo is None and hi is None and kind is not None:
            return self._facts_cached(Kind(kind), rules)
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

    def _facts_cached(self, kind: Kind, rules) -> list[StoredFact]:
        cache = self.__dict__.setdefault("_run_facts", {})
        runs = self.db.execute("SELECT id, rule, at FROM run WHERE current=1").fetchall()
        live = {(rid, at) for rid, _, at in runs}
        for k in [k for k in cache if k[:2] not in live]:         # a run recorded again: its old facts go
            del cache[k]
        want = set(rules) if rules else None
        chosen = [(rid, rule, at) for rid, rule, at in runs if want is None or rule in want]
        # the merged list of one selection of runs, kept while those runs stay current (most rules of a refresh
        # read the same kinds of the same runs)
        merged_key = ("merged", kind, tuple((rid, at) for rid, _, at in chosen))
        merged = self.__dict__.setdefault("_merged", {})
        hit = merged.get(merged_key)
        if hit is not None:
            return list(hit)
        rows = []
        # decoded facts by row id: a run recorded again in place (record_run writes only the facts that changed)
        # keeps the ids of its unchanged facts, so only the changed rows are decoded; a row counts as the same
        # only with the same rule and content (SQLite may give a deleted row's id to another)
        known = self.__dict__.setdefault("_rows", {})
        if len(known) > 1_000_000:
            known.clear()
        for n, (rid, rule, at) in enumerate(chosen):
            got = cache.get((rid, at, kind))          # (id, at): an id SQLite reuses after a delete is another run
            if got is None:
                # (lo, hi, value text, run, row, fact): the order of (lo, hi, value) with ties in run and row order,
                # as tuples that sort in C without touching the fact
                got = []
                for k, r in enumerate(self.db.execute(
                        "SELECT id, lo, hi, kind, value, level, by, reason FROM fact WHERE run_id=? AND kind=?", (rid, kind.value))):
                    hit = known.get(r[0])
                    if hit is not None and hit[0] == rule and hit[1] == r:
                        f = hit[2]
                    else:
                        f = self._row_fact((r[0], rule, *r[1:]))
                        known[r[0]] = (rule, r, f)
                    got.append((r[1], r[2], r[4], k, f))
                cache[(rid, at, kind)] = got
            rows.extend((lo, hi, v, n, k, f) for lo, hi, v, k, f in got)
        rows.sort()
        out = [r[5] for r in rows]
        if len(merged) > 256:
            merged.clear()
        live_keys = {(rid, at) for rid, _, at in runs}
        for k in [k for k in merged if not set(k[2]) <= live_keys]:
            del merged[k]
        merged[merged_key] = out
        return list(out)

    def fact(self, fid: int) -> StoredFact | None:
        row = self.db.execute("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f "
                              "JOIN run r ON r.id=f.run_id WHERE f.id=?", (fid,)).fetchone()
        return self._row_fact(row) if row else None

    def conflicts(self, severity: str | None = None, rules: tuple[str, ...] | None = None) -> list[Conflict]:
        """Conflicts of current runs (of the given rules), sorted by address."""
        q = ("SELECT c.severity, c.check_id, c.lo, c.hi, c.message, c.a, c.b FROM conflict c JOIN run r ON r.id=c.run_id "
             "WHERE r.current=1")
        args = []
        if severity:
            q += " AND c.severity=?"
            args.append(severity)
        if rules:
            q += " AND r.rule IN (%s)" % ",".join("?" * len(rules))
            args.extend(rules)
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
        (an analyzer's draft keyed by image and start) is replaced when `replace`."""
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        self.db.execute(f"{verb} INTO blob (hash, kind, data) VALUES (?, ?, ?)", (hash_, kind, data))

    def drop_blobs(self, kind: str):
        """Delete every blob of one kind from this store (never from the main store under an overlay)."""
        self.db.execute("DELETE FROM blob WHERE kind=?", (kind,))

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

    # ------------------------------------------------------------------ translation units
    TU_COLS = ("unit", "amalg", "src_hash", "flags", "flags_hash", "include_hash", "obj_hash", "ok", "log", "diags", "at")

    def tus(self) -> dict[str, dict]:
        """unit -> its tu row (flags and diags decoded)."""
        out = {}
        for row in self.db.execute(f"SELECT {', '.join(self.TU_COLS)} FROM tu ORDER BY unit"):
            d = dict(zip(self.TU_COLS, row))
            d["flags"] = json.loads(d["flags"])
            d["diags"] = json.loads(d["diags"])
            d["ok"] = bool(d["ok"])
            out[d["unit"]] = d
        return out

    TU_KEYS = ("unit", "amalg", "src_hash", "flags_hash", "include_hash", "obj_hash", "ok")

    def tu_keys(self) -> dict[str, dict]:
        """unit -> its tu row's keys and outcome only (TU_KEYS: no log, flags or diagnostics)."""
        out = {}
        for row in self.db.execute(f"SELECT {', '.join(self.TU_KEYS)} FROM tu ORDER BY unit"):
            d = dict(zip(self.TU_KEYS, row))
            d["ok"] = bool(d["ok"])
            out[d["unit"]] = d
        return out

    def put_tu(self, row: dict):
        vals = dict(row)
        vals["flags"] = canonical(list(vals["flags"]))
        vals["diags"] = canonical(list(vals["diags"]))
        vals["ok"] = int(bool(vals["ok"]))
        vals.setdefault("at", time.time())
        self.db.execute(f"INSERT OR REPLACE INTO tu ({', '.join(self.TU_COLS)}) VALUES ({', '.join('?' * len(self.TU_COLS))})",
                        tuple(vals[c] for c in self.TU_COLS))

    def drop_tu(self, unit: str):
        self.db.execute("DELETE FROM tu WHERE unit=?", (unit,))

    def tu_hash(self) -> str:
        """The hash of every tu row's inputs and outcome: the `objects` input of the match rules."""
        rows = self.db.execute("SELECT unit, src_hash, flags_hash, include_hash, obj_hash, ok, diags FROM tu ORDER BY unit").fetchall()
        return sha256(*(canonical(list(r)) for r in rows))

    def include_set(self, key: str) -> list[str] | None:
        row = self.db.execute("SELECT files FROM include_set WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_include_set(self, key: str, files: list[str]):
        self.db.execute("INSERT OR REPLACE INTO include_set (key, files) VALUES (?, ?)", (key, canonical(list(files))))

    # ------------------------------------------------------------------ bytemap
    def write_bytemap(self, rows: list[tuple], hash_: str):
        self.db.execute("BEGIN")
        self.db.execute("DELETE FROM bytemap")
        self.db.executemany("INSERT INTO bytemap (lo, hi, cls, level, symbol, unit, source, section) VALUES (?,?,?,?,?,?,?,?)", rows)
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('bytemap', ?)", (hash_,))
        self.db.execute("COMMIT")

    def bytemap_at(self, addr: int):
        """The byte map row holding addr (the map built first when its facts changed: query.ensure_bytemap)."""
        from .query import ensure_bytemap
        with timing.phase("bytemap"):
            ensure_bytemap(self)
        return self.db.execute("SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap WHERE lo<=? "
                               "ORDER BY lo DESC LIMIT 1", (addr,)).fetchone()

    def bytemap_rows(self, lo: int | None = None, hi: int | None = None):
        """The byte map rows intersecting [lo, hi) (the map built first when its facts changed)."""
        from .query import ensure_bytemap
        with timing.phase("bytemap"):
            ensure_bytemap(self)
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
