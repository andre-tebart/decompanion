"""The native core (native/dcp_core, Rust; docs/plan.md section 20): built on first use, loaded once per process.

`core()` is the extension module. It is built with cargo from native/dcp_core (rustup's x86_64-pc-windows-gnu
toolchain) and copied to build/native/_core-<profile>-<source hash>.pyd of the decompanion checkout, so a changed
crate builds a new module beside the old one (a loaded .pyd cannot be replaced on Windows). There is no Python
fallback: a missing cargo or a failed build is an error.

DCP_NATIVE_PROFILE picks the cargo profile: `dev` (the default; opt-level 1, incremental: a change builds in a few
seconds, for iterating and the tests) or `release` (thin LTO, one codegen unit: ~45 s a build, for timing).

DCP_SHADOW names what runs twice and is compared while it is being ported (a comma-separated list; `all` for
everything in shadow): the Python version is the reference and is deleted once the two agree on gildegold.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import threading
from pathlib import Path

CHECKOUT = Path(__file__).resolve().parents[2]
CRATE = CHECKOUT / "native" / "dcp_core"
_core = None
_lock = threading.Lock()


def source_hash() -> str:
    """The crate's sources: Cargo.toml, Cargo.lock and every file below src/."""
    h = hashlib.sha256()
    files = [CRATE / "Cargo.toml", CRATE / "Cargo.lock", *sorted((CRATE / "src").rglob("*"))]
    for f in files:
        if f.is_file():
            h.update(f.relative_to(CRATE).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()[:12]


def cargo() -> str:
    found = shutil.which("cargo")
    if found:
        return found
    home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo") / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")
    if home.exists():
        return str(home)
    raise RuntimeError("the native core needs cargo (rustup: `rustup default stable-x86_64-pc-windows-gnu`): not on PATH, "
                       f"not in {home.parent}")


def profile() -> str:
    p = os.environ.get("DCP_NATIVE_PROFILE") or "dev"
    if p not in ("dev", "release"):
        raise RuntimeError(f"DCP_NATIVE_PROFILE={p!r}: dev or release")
    return p


def core():
    """The extension module, built if the crate changed since the last build."""
    global _core
    if _core is not None:
        return _core
    with _lock:
        if _core is not None:
            return _core
        prof = profile()
        out = CHECKOUT / "build" / "native" / f"_core-{prof}-{source_hash()}.pyd"
        if not out.exists():
            r = subprocess.run([cargo(), "build", "--quiet", *(["--release"] if prof == "release" else [])], cwd=CRATE,
                               capture_output=True, text=True)
            built = CRATE / "target" / ("release" if prof == "release" else "debug") / ("_core.dll" if os.name == "nt" else "lib_core.so")
            if r.returncode != 0 or not built.exists():
                raise RuntimeError(f"building the native core ({CRATE}) failed:\n{r.stdout}{r.stderr}")
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_name(f"{out.stem}.{os.getpid()}.tmp")
            shutil.copyfile(built, tmp)
            try:
                os.replace(tmp, out)
            except OSError:                     # another process placed it meanwhile
                tmp.unlink(missing_ok=True)
        loader = importlib.machinery.ExtensionFileLoader("_core", str(out))
        spec = importlib.util.spec_from_file_location("_core", out, loader=loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        _core = mod
    return _core


def shadow(what: str) -> bool:
    """Whether DCP_SHADOW asks for `what` to be computed twice and compared."""
    s = {x.strip() for x in os.environ.get("DCP_SHADOW", "").split(",") if x.strip()}
    return what in s or "all" in s
