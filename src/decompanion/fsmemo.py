"""File contents read once per process: the input hashes, the source scan, the amalgamation and the grades all
read the same few thousand source files in one refresh. A read is memoised by (path, size, modification time);
the memo lives only as long as the process, so it never decides staleness (that is the content hashes' job),
it only saves the second read of an unchanged file.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

_bytes: dict[str, tuple[tuple[int, int], bytes]] = {}
_sha: dict[str, tuple[tuple[int, int], str]] = {}


def _stamp(path: str) -> tuple[int, int]:
    st = os.stat(path)
    return st.st_size, st.st_mtime_ns


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
    key = str(path)
    stamp = _stamp(key)
    hit = _sha.get(key)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    h = hashlib.sha256(read_bytes(key)).hexdigest()
    _sha[key] = (stamp, h)
    return h
