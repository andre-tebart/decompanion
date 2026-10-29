"""Analyzer plugins (the Analyzer seam, analyzers/base.py). A plugin registers its class with @register;
importing this package imports every plugin. `[analyzer] plugin = "<key>"` selects one; without the table (or
the key) the default `ghidra` is meant."""
from __future__ import annotations

ANALYZERS: dict[str, type] = {}
DEFAULT = "ghidra"


def register(cls):
    """Class decorator: make an Analyzer subclass available under its `key`."""
    ANALYZERS[cls.key] = cls
    return cls


def get(key: str | None):
    """The analyzer class `key` (None: the default), or None when no plugin has that key."""
    return ANALYZERS.get(key or DEFAULT)


def dialect(key: str):
    """An instance of the analyzer `key` without configuration: what reading its output needs (is_placeholder,
    rewrite, data_labels, types_header), never a run. The base Analyzer for an unknown key."""
    from .base import Analyzer
    return ANALYZERS.get(key, Analyzer)({}, None)


from . import ghidra, none, rea  # noqa: E402,F401  (registers)
