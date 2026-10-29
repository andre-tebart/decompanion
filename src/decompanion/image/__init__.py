"""Image-format plugins (the Image seam, image/base.py). A plugin registers its class with @register;
importing this package imports every plugin. A target names its format with `image = "<key>"`; `dcp init` and
`dcp target add` find it by opening the binary with each registered format (open_image)."""
from __future__ import annotations

from pathlib import Path

FORMATS: dict[str, type] = {}


def register(cls):
    """Class decorator: make an Image subclass available under its `key`."""
    FORMATS[cls.key] = cls
    return cls


def default_key() -> str | None:
    """The key of the only registered image format; None when there are several."""
    return next(iter(FORMATS)) if len(FORMATS) == 1 else None


def open_image(path: Path):
    """(key, image) of the first registered format that reads the file; ValueError when none does."""
    errors = []
    for key, cls in FORMATS.items():
        try:
            return key, cls(path)
        except ValueError as ex:
            errors.append(f"{key}: {ex}")
    raise ValueError(f"{path}: no image format reads it ({'; '.join(errors) or 'no format registered'})")


from . import pe32  # noqa: E402,F401  (registers)
