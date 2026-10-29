"""Instruction-set plugins (the Isa seam, isa/base.py). A plugin module registers its class with @register;
importing this package imports every plugin. A target names its ISA with `isa = "<key>"` in its [[target]]
table, else the image format derives it from the machine type (Image.default_isa)."""
from __future__ import annotations

ISAS: dict[str, type] = {}


def register(cls):
    """Class decorator: make an Isa subclass available under its `key`."""
    ISAS[cls.key] = cls
    return cls


def get(key: str):
    """An instance of the ISA plugin `key`, or None when no plugin has that key."""
    cls = ISAS.get(key)
    return cls() if cls is not None else None


from . import x86  # noqa: E402,F401  (registers)
