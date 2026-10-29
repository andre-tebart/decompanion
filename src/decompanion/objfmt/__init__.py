"""Object-format plugins (the ObjectFormat seam, objfmt/base.py). A plugin registers its class with @register;
importing this package imports every plugin. The toolchain names the format of its objects
(Toolchain.object_format)."""
from __future__ import annotations

FORMATS: dict[str, type] = {}


def register(cls):
    """Class decorator: make an ObjectFormat subclass available under its `key`."""
    FORMATS[cls.key] = cls
    return cls


def get(key: str):
    """An instance of the object-format plugin `key`, or None when no plugin has that key."""
    cls = FORMATS.get(key)
    return cls() if cls is not None else None


from . import coff  # noqa: E402,F401  (registers)
