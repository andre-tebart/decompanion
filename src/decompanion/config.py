"""The target project: decompanion.toml and everything that hangs off it (the image, the toolchain plugin,
the store, the named external inputs with their content hashes).

decompanion.toml
  [target]       path = "...server.dll"  sha256 = "..."  image = "pe32"
  [toolchain]    plugin = "vc6"  root = "C:/Tools/MSVC600-SP5PP"  compiler = "cl 12.00.9044"  linker = "link 6.00.8447"
                 cflags = ["/O2", "/Gy"]  reason = "..."     (declared; the probe proves flags per unit later)
  [libs]         archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB", ...]
  [sources]      roots = ["src"]  include = ["include"]
"""
from __future__ import annotations

import hashlib
import tomllib
from functools import cached_property
from pathlib import Path

from .image.pe32 import PE32
from .ledger.store import Store, file_hash
from .toolchains.vc6 import VC6

IMAGE_FORMATS = {"pe32": PE32}
TOOLCHAINS = {"vc6": VC6}
CONFIG_NAME = "decompanion.toml"


class ConfigError(RuntimeError):
    pass


def find_root(start: Path | None = None) -> Path:
    p = (start or Path.cwd()).resolve()
    for d in (p, *p.parents):
        if (d / CONFIG_NAME).exists():
            return d
    raise ConfigError(f"no {CONFIG_NAME} in {p} or above (run dcp init)")


class Project:
    def __init__(self, root: Path | None = None):
        self.root = find_root(root) if root is None or not (Path(root) / CONFIG_NAME).exists() else Path(root).resolve()
        self.config_path = self.root / CONFIG_NAME
        self.cfg = tomllib.loads(self.config_path.read_text())
        t = self.cfg.get("target") or {}
        if "path" not in t:
            raise ConfigError(f"{self.config_path}: [target] path missing")
        self.target = self.expand(t["path"])
        self.declared_sha = t.get("sha256", "")
        self.image_format = t.get("image", "pe32")
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

    # ------------------------------------------------------------------ objects
    @cached_property
    def image(self):
        fmt = IMAGE_FORMATS.get(self.image_format)
        if fmt is None:
            raise ConfigError(f"unknown image format {self.image_format!r}")
        if not self.target.exists():
            raise ConfigError(f"target {self.target} does not exist")
        img = fmt(self.target)
        if self.declared_sha and img.sha256 != self.declared_sha:
            raise ConfigError(f"target {self.target}: sha256 {img.sha256} differs from the declared {self.declared_sha}")
        return img

    @cached_property
    def store(self) -> Store:
        main = None
        marker = self.root / ".dcp" / "main_store"
        if marker.exists():
            main = Path(marker.read_text().strip())
        return Store(self.build_dir / "dcp.sqlite", overlay_of=main)

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
            h = file_hash(self.target)
        elif name == "config":
            h = file_hash(self.config_path)
        elif name == "libs":
            h = hashlib.sha256(b"".join(f"{p.name}:{file_hash(p)}\n".encode() for p in self.lib_archives)).hexdigest()
        elif name == "decl":
            h = self.tree_hash([self.root / "decl"], ("*.dcl",))
        elif name == "src":
            h = self.tree_hash([self.root / "src", self.root / "include"], ("*.c", "*.h"))
        else:
            raise ConfigError(f"unknown input {name!r}")
        self._hashes[name] = h
        return h

    @staticmethod
    def tree_hash(dirs: list[Path], patterns: tuple[str, ...]) -> str:
        h = hashlib.sha256()
        for d in dirs:
            if not d.exists():
                continue
            for pat in patterns:
                for p in sorted(d.rglob(pat)):
                    h.update(str(p.relative_to(d)).encode())
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
            return self.root / "src"
        raise ConfigError(f"unknown input {name!r}")
