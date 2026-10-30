"""File contents and content hashes, read once: the input hashes, the source scan, the units and the grades
all read the same few thousand source files in one refresh, and every command (every request of `dcp serve`)
hashes the whole tree again.

- A read is memoised by (path, size, modification time) for the life of the process.
- A stamp (size, modification time) is taken once per epoch: `walk` lists a tree with the stamps the directory
  listing carries (no stat per file), `_stamp` stats a path not seen yet. `new_epoch` forgets the stamps; it
  runs at the start of every command, refresh and build, and after every write of a source file by dcp itself
  (`wrote`), so a file changed between two epochs is always seen.
- The content hash of a file is persisted per project (build/cache/stamps.pickle: path -> size, modification
  time, sha256, when it was hashed), so a new process does not read an unchanged file to hash it. An entry is
  trusted only when the stamp is equal and the file was last modified more than RACY_NS before it was hashed
  (git's racy-clean rule: a write within the same clock tick as the hash could keep the stamp). DCP_NO_STAMPS=1
  turns the persisted hashes off; `dcp build --force` and `dcp setup --force` drop them (forget_all).

The stamps decide nothing on their own beyond "this file did not change": every input hash is still the content
hash of the files.
"""
from __future__ import annotations

import hashlib
import os
import pickle
import time
from pathlib import Path

_bytes: dict[str, tuple[tuple[int, int], bytes]] = {}
_sha: dict[str, tuple[tuple[int, int], str]] = {}
_seen: dict[str, tuple[int, int]] = {}            # path -> stamp, this epoch

STAMPS_VERSION = 2
RACY_NS = 2_000_000_000
DERIVED_MAX = 20000
_disk: dict[str, tuple[int, int, str, int]] = {}  # path -> (size, mtime_ns, sha256, hashed at ns)
_derived: dict[str, str] = {}                     # a content-keyed value computed from files (amalg src_hash)
_disk_path: Path | None = None
_dirty = False


epoch = 0                                         # counts new_epoch(): what is memoised per epoch keys on it


def new_epoch():
    """Forget every stamp taken so far: the next look at a file stats it (or lists its directory) again."""
    global epoch
    _seen.clear()
    epoch += 1


def wrote(path=None):
    """dcp wrote (or removed, or renamed) a file: forget the stamps."""
    new_epoch()


def _stamp(path: str) -> tuple[int, int]:
    s = _seen.get(path)
    if s is None:
        st = os.stat(path)
        s = _seen[path] = (st.st_size, st.st_mtime_ns)
    return s


def walk(base: Path, patterns: tuple[str, ...]) -> list[tuple[str, str]]:
    """The files below base matching any of the name patterns (fnmatch, case-insensitive) as (path relative to
    base in posix spelling, full path), in the order of sorted(base.rglob(pattern)) per pattern, each pattern's
    files once; the directory listing's stamps are noted for the epoch."""
    import fnmatch
    base = Path(base)
    found: list[tuple[tuple, str]] = []
    pats = [p.lower() for p in patterns]

    def rec(d: str, parts: tuple, rel: str):
        try:
            it = os.scandir(d)
        except OSError:
            return
        with it:
            for e in it:
                if e.is_dir(follow_symlinks=False):
                    rec(e.path, parts + (e.name.lower(),), rel + e.name + "/")
                elif e.is_file():
                    st = e.stat()
                    _seen[e.path] = (st.st_size, st.st_mtime_ns)
                    found.append((parts + (e.name.lower(),), rel + e.name, e.path))

    rec(str(base), (), "")
    out = []
    for pat in pats:
        out.extend((r, p) for _, r, p in sorted(t for t in found if fnmatch.fnmatchcase(t[0][-1], pat)))
    return out


def read_bytes(path) -> bytes:
    key = str(path)
    stamp = _stamp(key)
    hit = _bytes.get(key)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    data = Path(key).read_bytes()
    _bytes[key] = (stamp, data)
    return data


def read_text(path) -> str:
    """The text as Path.read_text(errors="replace") gives it (UTF-8, universal newlines)."""
    data = read_bytes(path).decode("utf-8", errors="replace")
    return data.replace("\r\n", "\n").replace("\r", "\n")


def sha256(path) -> str:
    """The hex sha256 of the file's bytes."""
    global _dirty
    key = str(path)
    stamp = _stamp(key)
    hit = _sha.get(key)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    d = _disk.get(key)
    if d is not None and (d[0], d[1]) == stamp and d[1] < d[3] - RACY_NS:
        _sha[key] = (stamp, d[2])
        return d[2]
    h = hashlib.sha256(read_bytes(key)).hexdigest()
    _sha[key] = (stamp, h)
    if _disk_path is not None:
        _disk[key] = (stamp[0], stamp[1], h, time.time_ns())
        _dirty = True
    return h


# ------------------------------------------------------------------ the persisted hashes
def attach(root: Path):
    """Use the persisted hashes of the project at root (once per process and root)."""
    global _disk_path, _dirty
    if os.environ.get("DCP_NO_STAMPS") or os.environ.get("DCP_NO_SHORTCUTS"):
        return
    path = Path(root) / "build" / "cache" / "stamps.pickle"
    if _disk_path == path:
        return
    flush()
    _disk.clear()
    _derived.clear()
    _dirty = False
    _disk_path = path
    try:
        version, data, derived_ = pickle.loads(path.read_bytes())
        if version == STAMPS_VERSION:
            _disk.update(data)
            _derived.update(derived_)
    except (OSError, ValueError, EOFError, pickle.UnpicklingError, TypeError):
        pass


def flush():
    """Write the persisted hashes when they changed (atomically: another process may read them meanwhile)."""
    global _dirty
    if not _dirty or _disk_path is None:
        return
    try:
        _disk_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = _disk_path.with_name(f"{_disk_path.name}.{os.getpid()}.tmp")
        while len(_derived) > DERIVED_MAX:
            del _derived[next(iter(_derived))]
        tmp.write_bytes(pickle.dumps((STAMPS_VERSION, _disk, _derived)))
        os.replace(tmp, _disk_path)
        _dirty = False
    except OSError:
        pass


def forget_all():
    """Drop every memo and the persisted hashes (a forced rebuild trusts no stamp)."""
    global _dirty
    _bytes.clear()
    _sha.clear()
    _seen.clear()
    _disk.clear()
    _derived.clear()
    _dirty = _disk_path is not None


def derived(key: str) -> str | None:
    """A value memoised under a key that hashes everything it was computed from (put_derived)."""
    return _derived.get(key)


def put_derived(key: str, value: str):
    global _dirty
    _derived[key] = value
    _dirty = True
