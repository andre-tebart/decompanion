"""Toolchain plugins (the Toolchain seam, toolchains/base.py). A plugin registers its class with @register;
importing this package imports every plugin. `[toolchain] plugin = "<key>"` selects one; without the key, the
only registered plugin is meant."""
from __future__ import annotations

TOOLCHAINS: dict[str, type] = {}


def register(cls):
    """Class decorator: make a Toolchain subclass available under its `key`."""
    TOOLCHAINS[cls.key] = cls
    return cls


def default_key() -> str | None:
    """The key of the only registered toolchain plugin; None when there are several."""
    return next(iter(TOOLCHAINS)) if len(TOOLCHAINS) == 1 else None


from . import vc6  # noqa: E402,F401  (registers)
