"""The target project: decompanion.toml and everything that hangs off it (the targets and their images, the
toolchain plugin, one store per target, the named external inputs with their content hashes).

decompanion.toml
  [[target]]     name = "server"  path = "...server.dll"  sha256 = "..."  image = "pe32"
                 (one table per binary built from the codebase; the first is the default target)
  [toolchain]    plugin = "vc6"  root = "C:/Tools/MSVC600-SP5PP"  compiler = "cl 12.00.9044"  linker = "link 6.00.8447"
                 cflags = ["/O2", "/Gy"]  reason = "..."     (declared; the probe proves flags per unit later)
  [libs]         archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB", ...]
  [sources]      roots = ["src"]  include = ["include"]

The single-table form `[target]` of milestone 1 is still read (one target named after the file's stem); `dcp
target add` rewrites it into the list form.

Every target has its own store, build/<target>.sqlite: facts are intervals of one address space and carry no
target column. A worktree made by `dcp wt new` names the main checkout's build directory in .dcp/main_store;
its stores overlay main's store of the same target (lookups go overlay first, then main).
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from .image.pe32 import PE32
from .ledger.store import Store, file_hash, sha256
from .toolchains.vc6 import VC6

IMAGE_FORMATS = {"pe32": PE32}
TOOLCHAINS = {"vc6": VC6}
CONFIG_NAME = "decompanion.toml"
TARGET_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Target:
    name: str
    path: Path
    sha256: str
    image: str = "pe32"
    legacy: bool = False       # read from the single-table [target] form


def find_root(start: Path | None = None) -> Path:
    p = (start or Path.cwd()).resolve()
    for d in (p, *p.parents):
        if (d / CONFIG_NAME).exists():
            return d
    raise ConfigError(f"no {CONFIG_NAME} in {p} or above (run dcp init)")


def target_name_of(path: Path) -> str:
    """The default name of a target: the binary's stem, lower case, reduced to [a-z0-9_-]."""
    n = re.sub(r"[^a-z0-9_-]", "_", Path(path).stem.lower())
    return n if n and n[0].isalpha() else "t" + n


def parse_targets(cfg: dict, expand) -> list[Target]:
    t = cfg.get("target")
    if t is None:
        raise ConfigError(f"{CONFIG_NAME}: no [[target]] table")
    legacy = isinstance(t, dict)
    tables = [t] if legacy else list(t)
    out = []
    for i, tab in enumerate(tables):
        if "path" not in tab:
            raise ConfigError(f"{CONFIG_NAME}: target #{i + 1} has no path")
        path = expand(tab["path"])
        name = tab.get("name") or target_name_of(path)
        if not TARGET_NAME.match(name):
            raise ConfigError(f"{CONFIG_NAME}: target name {name!r} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)")
        if any(o.name == name for o in out):
            raise ConfigError(f"{CONFIG_NAME}: target {name!r} declared twice")
        out.append(Target(name, path, tab.get("sha256", ""), tab.get("image", "pe32"), legacy))
    if not out:
        raise ConfigError(f"{CONFIG_NAME}: the [[target]] list is empty")
    return out


class Project:
    def __init__(self, root: Path | None = None, target: str | None = None):
        self.root = find_root(root) if root is None or not (Path(root) / CONFIG_NAME).exists() else Path(root).resolve()
        self.config_path = self.root / CONFIG_NAME
        self.cfg = tomllib.loads(self.config_path.read_text())
        self.targets = parse_targets(self.cfg, self.expand)
        self.target_name = self.target(target).name     # the current target (default: the first)
        tc = self.cfg.get("toolchain") or {}
        plugin = TOOLCHAINS.get(tc.get("plugin", "vc6"))
        if plugin is None:
            raise ConfigError(f"unknown toolchain plugin {tc.get('plugin')!r}")
        self.toolchain = plugin(self.expand(tc["root"]) if tc.get("root") else None, tc)
        self.build_dir = self.root / "build"
        self._hashes: dict[str, str] = {}

    def expand(self, s: str) -> Path:
        tc = self.cfg.get("toolchain") or {}
        s = s.replace("{toolchain.root}", str(tc.get("root", "")))
        p = Path(s)
        return p if p.is_absolute() else (self.root / p)

    # ------------------------------------------------------------------ targets
    def target(self, name: str | None = None) -> Target:
        """The named target; None: the current one (the default target before the selection is made)."""
        if name is None:
            name = getattr(self, "target_name", None)
            if name is None:
                return self.targets[0]
        for t in self.targets:
            if t.name == name:
                return t
        raise ConfigError(f"no target {name!r} (targets: {', '.join(t.name for t in self.targets)})")

    @property
    def default_target(self) -> str:
        return self.targets[0].name

    def for_target(self, name: str) -> "Project":
        """The same project with another target selected (its own image and store)."""
        return Project(self.root, name)

    @property
    def image_path(self) -> Path:
        return self.target().path

    @property
    def declared_sha(self) -> str:
        return self.target().sha256

    @property
    def image_format(self) -> str:
        return self.target().image

    def store_path(self, name: str | None = None) -> Path:
        return self.build_dir / f"{self.target(name).name}.sqlite"

    def main_build_dir(self) -> Path | None:
        """The main checkout's build directory when this checkout is a worktree (.dcp/main_store), else None.
        The marker of milestone 1 named a store file; its directory is meant."""
        marker = self.root / ".dcp" / "main_store"
        if not marker.exists():
            return None
        p = Path(marker.read_text().strip())
        return p.parent if p.suffix == ".sqlite" else p

    # ------------------------------------------------------------------ objects
    @cached_property
    def image(self):
        t = self.target()
        fmt = IMAGE_FORMATS.get(t.image)
        if fmt is None:
            raise ConfigError(f"unknown image format {t.image!r}")
        if not t.path.exists():
            raise ConfigError(f"target {t.name}: {t.path} does not exist")
        img = fmt(t.path)
        if t.sha256 and img.sha256 != t.sha256:
            raise ConfigError(f"target {t.name}: {t.path} has sha256 {img.sha256}, the declared one is {t.sha256}")
        return img

    @cached_property
    def store(self) -> Store:
        main = self.main_build_dir()
        overlay = main / f"{self.target_name}.sqlite" if main is not None else None
        return Store(self.store_path(), overlay_of=overlay)

    @cached_property
    def lib_archives(self) -> list[Path]:
        libs = (self.cfg.get("libs") or {}).get("archives") or []
        out = []
        for s in libs:
            p = self.expand(s)
            if not p.exists():
                raise ConfigError(f"[libs] archive {p} does not exist")
            out.append(p)
        return out

    @property
    def toolchain_decl(self) -> dict:
        return dict(self.cfg.get("toolchain") or {})

    # ------------------------------------------------------------------ inputs
    def input_hash(self, name: str) -> str:
        if name in self._hashes:
            return self._hashes[name]
        if name == "image":
            h = file_hash(self.image_path)
        elif name == "config":
            h = file_hash(self.config_path)
        elif name == "libs":
            h = hashlib.sha256(b"".join(f"{p.name}:{file_hash(p)}\n".encode() for p in self.lib_archives)).hexdigest()
        elif name == "decl":
            h = self.tree_hash([self.root / "decl"], ("*.dcl",))
        elif name == "src":
            h = self.tree_hash([self.root / "src", self.root / "include"], ("*.c", "*.h"))
        elif name == "ghidra":
            st = self.store
            h = sha256(st.main_meta("ghidra") or "", st.meta("ghidra") or "")
        else:
            raise ConfigError(f"unknown input {name!r}")
        self._hashes[name] = h
        return h

    def forget_input(self, name: str):
        """Drop a memoised input hash (after a command changed the input, e.g. `dcp ghidra import`)."""
        self._hashes.pop(name, None)

    @staticmethod
    def tree_hash(dirs: list[Path], patterns: tuple[str, ...]) -> str:
        h = hashlib.sha256()
        for d in dirs:
            if not d.exists():
                continue
            h.update(d.name.encode() + b"\1")
            for pat in patterns:
                for p in sorted(d.rglob(pat)):
                    h.update(p.relative_to(d).as_posix().encode())
                    h.update(b"\0")
                    h.update(hashlib.sha256(p.read_bytes()).digest())
        return h.hexdigest()

    def input(self, name: str):
        if name == "image":
            return self.image
        if name == "config":
            return self.cfg
        if name == "libs":
            return self.lib_archives
        if name == "decl":
            return sorted((self.root / "decl").glob("*.dcl")) if (self.root / "decl").exists() else []
        if name == "src":
            return self.root
        if name == "ghidra":
            from .ledger import ghidra
            return ghidra.entries(self.store)
        raise ConfigError(f"unknown input {name!r}")
