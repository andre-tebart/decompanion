"""The compile: every stale translation unit of a target through the toolchain, one compiler process per unit
in a thread pool, the objects content-addressed under build/obj/<sha256>.obj, the outcome in the store's `tu`
table.

A unit is stale iff one of three hashes differs from its tu row: the source hash (the amalgamation's text),
the flags hash (the target's cflags plus the unit's override), or the include hash (the contents of every
file in the unit's actual include set). The include set comes from the preprocessor (Toolchain.includes) and
is cached in the store by (source hash, flags hash, listing hash of every include search directory): it can
only change when the unit's text, its flags, a file in the set, or a directory listing changes, and a changed
file in the set already makes the unit stale, after which the set is read again. So an edited header
recompiles exactly the units that include it (the header-edit trap of the first attempt, where a global
headers digest recompiled all units).

A failed unit keeps a row with ok=0, its log and diagnostics and its input hashes (it is not compiled again
until an input changes); M.compile turns it into a `build` fact with ok=false and a gate error. Nothing here
reads a modification time.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ..ledger import srcscan
from ..ledger.fact import canonical
from ..ledger.store import sha256
from . import amalg as A


@dataclass
class Report:
    target: str
    units: int = 0
    compiled: list = field(default_factory=list)    # units compiled this run
    failed: list = field(default_factory=list)      # units whose compile failed this run
    removed: list = field(default_factory=list)     # tu rows of units that are gone
    preprocessed: int = 0
    ms: int = 0
    unavailable: bool = False                       # the toolchain is not installed: nothing compiled


def unit_overrides(project) -> list[dict]:
    """The [[toolchain.unit]] tables: glob (on the unit name), cflags, reason, optional targets."""
    tc = project.cfg.get("toolchain") or {}
    out = tc.get("unit") or []
    return out if isinstance(out, list) else []


def flags_for(project, target: str, unit: str) -> tuple[list[str], dict | None]:
    """(flags, the override table that applied or None): the target's declared cflags, then the cflags of the
    first [[toolchain.unit]] whose glob matches the unit name (and whose `targets`, when given, list the
    target)."""
    flags = list(project.toolchain_decl_for(target).get("cflags") or [])
    for o in unit_overrides(project):
        if o.get("targets") and target not in o["targets"]:
            continue
        if fnmatch.fnmatchcase(unit, str(o.get("glob", ""))):
            return flags + list(o.get("cflags") or []), o
    return flags, None


def include_dirs(unit: str) -> list[Path]:
    """The include directories of a unit, relative to the project root: its own directory (a quoted include
    in head.c resolves there although the compiler reads the amalgamation) and include/."""
    return [Path("src") / unit, Path("include")]


_listing: dict[tuple, str] = {}


def listing_hash(dirs: list[Path]) -> str:
    """The hash of the names (not the contents) of every file below the directories: a new header that
    shadows another changes it. Memoised per process."""
    key = tuple(str(d) for d in dirs)
    h = _listing.get(key)
    if h is None:
        hh = hashlib.sha256()
        for d in dirs:
            hh.update(str(d).encode() + b"\1")
            if not d.exists():
                continue
            for base, subdirs, files in os.walk(d):
                subdirs.sort()
                for f in sorted(files):
                    hh.update(os.path.relpath(os.path.join(base, f), d).lower().encode() + b"\0")
        h = _listing[key] = hh.hexdigest()
    return h


class Hasher:
    """Content hashes of include files, one read per file per run."""

    def __init__(self):
        self.memo: dict[str, str] = {}

    def file(self, path: str) -> str:
        h = self.memo.get(path)
        if h is None:
            p = Path(path)
            h = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "missing"
            self.memo[path] = h
        return h

    def set(self, files: list[str]) -> str:
        return sha256(*(f"{f.lower()}={self.file(f)}" for f in sorted(files, key=str.lower)))


def plan(project, scan=None) -> list[A.Amalg]:
    """The amalgamations of the project's current target."""
    if scan is None:
        scan = srcscan.scan(project.root, project.input_hash("src"))
    return A.units(project.root, scan, project.target_name, project.default_target)


def obj_path(root: Path, obj_hash: str) -> Path:
    return Path(root) / "build" / "obj" / f"{obj_hash}.obj"


def ensure(project, log=None, force: bool = False, jobs: int | None = None) -> Report:
    """Bring the objects of the current target up to date (see the module docstring)."""
    t0 = time.perf_counter()
    root = project.root
    tc = project.toolchain
    st = project.store
    rep = Report(project.target_name)
    amalgs = plan(project)
    rep.units = len(amalgs)
    if amalgs and not tc.available():
        rep.unavailable = True
        if log:
            log(f"build: the toolchain is not available (root {tc.root}): {len(amalgs)} units not compiled")
        return rep
    rows = st.tus()
    hasher = Hasher()
    todo_pre, work = [], {}
    for a in amalgs:
        A.write(root, a)
        flags, _ = flags_for(project, a.target, a.unit)
        dirs = include_dirs(a.unit)
        search = [Path(root, d) if not Path(d).is_absolute() else Path(d) for d in tc.include_search_dirs(dirs)]
        key = sha256(a.src_hash, sha256(canonical(flags)), listing_hash(search))
        work[a.unit] = (a, flags, dirs, key)
        if st.include_set(key) is None:
            todo_pre.append(a.unit)
    ours = {a.unit: {str((Path(root) / m.file).resolve()).lower() for m in a.members} for a in amalgs}

    def preprocess(unit):
        """(unit, include set or None when the preprocessor fails)."""
        a, flags, dirs, key = work[unit]
        files, err = tc.includes(Path(a.path), flags, dirs, root)
        if err:
            return unit, None
        return unit, [str(f) for f in files if str(f).lower() not in ours[unit]]

    n = jobs or os.cpu_count() or 4
    if todo_pre:
        with ThreadPoolExecutor(n) as pool:
            for unit, files in pool.map(preprocess, todo_pre):
                if files is not None:
                    st.put_include_set(work[unit][3], files)
                rep.preprocessed += 1
    stale = []
    for unit, (a, flags, dirs, key) in work.items():
        files = st.include_set(key)
        row = rows.get(unit)
        fh = sha256(canonical(flags))
        # a unit whose include set is unknown (the preprocessor failed) is always stale: a fix in any header
        # must reach it
        fresh = (files is not None and row is not None and not force and row["src_hash"] == a.src_hash
                 and row["flags_hash"] == fh and row["include_hash"] == hasher.set(files) and row["amalg"] == a.path
                 and (not row["ok"] or obj_path(root, row["obj_hash"]).exists()))
        if not fresh:
            stale.append(unit)

    def compile_one(unit):
        a, flags, dirs, key = work[unit]
        tmp = Path("build") / "obj" / "tmp" / a.target / f"{a.unit}.obj"
        (root / tmp).parent.mkdir(parents=True, exist_ok=True)
        if (root / tmp).exists():
            (root / tmp).unlink()
        res = tc.compile(Path(a.path), tmp, flags, dirs, root)
        _, files = preprocess(unit)                                   # the set as the unit reads it now
        obj_hash = ""
        if res.ok:
            data = (root / tmp).read_bytes()
            obj_hash = hashlib.sha256(data).hexdigest()
            dest = obj_path(root, obj_hash)
            if dest.exists():
                (root / tmp).unlink()
            else:
                os.replace(root / tmp, dest)
        return unit, res, files, obj_hash

    if stale:
        if log:
            log(f"build: compiling {len(stale)} of {len(amalgs)} units (target {project.target_name})")
        with ThreadPoolExecutor(n) as pool:
            results = list(pool.map(compile_one, stale))
        for unit, res, files, obj_hash in results:
            a, flags, dirs, key = work[unit]
            if files is not None:
                st.put_include_set(key, files)
            st.put_tu({"unit": unit, "amalg": a.path, "src_hash": a.src_hash, "flags": flags,
                       "flags_hash": sha256(canonical(flags)), "include_hash": hasher.set(files) if files is not None else "unknown",
                       "obj_hash": obj_hash,
                       "ok": res.ok, "log": res.log, "diags": [[d.file, d.line, d.severity, d.code, d.message] for d in res.diagnostics]
                       + [["", 0, "error", "refused", f] for f in res.refused_flags]})
            rep.compiled.append(unit)
            if not res.ok:
                rep.failed.append(unit)
            if log:
                errs = [d for d in res.diagnostics if d.severity == "error"]
                warns = [d for d in res.diagnostics if d.severity == "warning"]
                log(f"  {'ok  ' if res.ok else 'FAIL'} {unit}  errors={len(errs)} warnings={len(warns)}"
                    + (f"  obj={obj_hash[:12]}" if obj_hash else ""))
                for d in errs[:10]:
                    log("       " + d.text())
    for unit in sorted(set(rows) - set(work)):
        st.drop_tu(unit)
        rep.removed.append(unit)
    project.forget_input("objects")
    rep.ms = int((time.perf_counter() - t0) * 1000)
    return rep
