"""File contents and content hashes, read once per stamp (size, modification time) and persisted per project
(build/cache/stamps.tsv): the core's (native/dcp_core/src/fsmemo.rs, where the rules are stated). This module is
its face: `new_epoch` at the start of every command, refresh and build and after every write of a source file by
dcp itself (`wrote`), so a file changed between two epochs is always seen.
"""
from __future__ import annotations

from . import native

_core = native.core()


def new_epoch():
    """Forget every stamp taken so far: the next look at a file stats it (or lists its directory) again."""
    _core.fs_new_epoch()


def wrote(path=None):
    """dcp wrote (or removed, or renamed) a file: forget the stamps."""
    _core.fs_new_epoch()


def epoch() -> int:
    """How many epochs have begun (what is memoised per epoch keys on it)."""
    return _core.fs_epoch()


def exists(path) -> bool:
    return _core.fs_exists(str(path))


def walk(base, patterns: tuple[str, ...]) -> list[tuple[str, str]]:
    """The files below base matching any of the name patterns (case-insensitive) as (posix path relative to base,
    full path), sorted per pattern."""
    return _core.fs_walk(str(base), list(patterns))


def read_bytes(path) -> bytes:
    return _core.fs_read_bytes(str(path))


def read_text(path) -> str:
    """The text as Path.read_text(errors="replace") gives it (UTF-8, universal newlines)."""
    return _core.fs_read_text(str(path))


def sha256(path) -> str:
    return _core.fs_sha256(str(path))


def tree_hash(dirs, patterns: tuple[str, ...]) -> str:
    return _core.fs_tree_hash([str(d) for d in dirs], list(patterns))


def attach(root):
    _core.fs_attach(str(root))


def flush():
    _core.fs_flush()


def forget_all():
    _core.fs_forget_all()
