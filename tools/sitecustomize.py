"""Project-wide Python defaults for the decomp toolchain.

This file is installed into the venv as the top-level `sitecustomize` module (pyproject.toml:
`py-modules = ["sitecustomize"]`, package dir `tools`). CPython's `site` module imports a
module of that name at startup, so every `uv run ...` gets these defaults; nothing has to
remember to set a flag. uv installs the project in editable mode, so the module loaded is this
file (edit it and the next run has the change).

Why it exists: on Windows, text-mode writes default to CRLF (`newline=None` -> os.linesep),
which silently corrupts the repo's LF contract (.gitattributes `* text=auto eol=lf`,
.editorconfig, uv run enc). An ad-hoc `Path.write_text(s)` by a worker must not rewrite a
source file as CRLF, so the default is changed here: text writes are LF unless the caller
passes `newline=` explicitly.

Reads are untouched (universal newlines still normalise any stray CRLF on the way in);
explicit `newline=` values are respected; binary modes are unaffected. Encoding stays the
interpreter's PEP 686 default (UTF-8 on Python 3.15), so nothing here touches encoding.
"""
import builtins
import io

_orig_open = io.open


def _open(file, mode="r", buffering=-1, encoding=None, errors=None,
          newline=None, closefd=True, opener=None):
    # Write-capable TEXT modes default to LF. Binary modes ('b') take no newline at all, and
    # 'r+' (read+write, no w/a/x) is left alone: forcing newline there would also disable
    # universal-newline reading.
    if newline is None and isinstance(mode, str) and "b" not in mode and any(c in mode for c in "wax"):
        newline = "\n"
    return _orig_open(file, mode, buffering, encoding, errors, newline, closefd, opener)


# open() (builtins) and io.open()/Path.write_text() (pathlib calls io.open) are the same
# underlying function but distinct names, so both are rebound.
io.open = _open
builtins.open = _open
