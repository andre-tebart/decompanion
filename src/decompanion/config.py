"""The target project: decompanion.toml and everything that hangs off it (the targets and their images, the
toolchain plugin, one store per target, the named external inputs with their content hashes).

decompanion.toml
  [[target]]     name = "server"  path = "...server.dll"  sha256 = "..."  image = "pe32"  isa = "x86"
                 (computed by `dcp init` / `dcp target add` from the file: image is the image-format plugin that
                 reads it, isa the instruction set its machine type implies)
                 compiler = "cl 12.00.9044"  linker = "link 6.00.8447"  cflags = ["/O2", "/Gy"]
                 archives = ["{toolchain.root}/VC98/Lib/LIBCMT.LIB"]
                 reason.compiler = "..."  reason.linker = "..."  reason.cflags = "..."  reason.archives = "..."
                 (declarations: written by `dcp toolchain declare` / `dcp libs declare`, each with its reason;
                 never by the tool on its own. The older form `reason = "..."` covers every key of its table.
                 One table per binary built from the codebase; the first is the default target; the toolchain
                 declaration is per target: binaries of one tree may still differ in what built them)
  [toolchain]    plugin = "vc6"  root = "C:/Tools/MSVC600-SP5PP"  reason.root = "..."
                 (plugin default: the only registered one; compiler / linker / cflags here are defaults a
                 target without its own inherits, with their reasons)
  [libs]         archives = [...]  reason = "..."     (the default of every target without its own archives)
  [sources]      roots = ["src"]  include = ["include"]
  [analyzer]     plugin = "ghidra"  root = "C:/Tools/ghidra_12.1.4_PUBLIC"  java_home = "..."  timeout = 60
                 (the third-party analyzer `dcp setup` runs for drafts; default: ghidra; "none" exports nothing)

The plugins (image format, toolchain, object format, instruction set, analyzer) come from the registries of
their packages; this module names none of them.

The single-table form `[target]` of milestone 1 is still read (one target named after the file's stem); `dcp
target add` rewrites it into the list form.

Every target has its own store, build/<target>.sqlite: facts are intervals of one address space and carry no
target column. A worktree made by `dcp wt new` names the main checkout's build directory in .dcp/main_store;
its stores overlay main's store of the same target (lookups go overlay first, then main).

The configuration, the declarations and the input hashes are the core's (native/dcp_core/src/project.rs); this
module adds the plugins' objects (image, toolchain, object format, instruction set, analyzer) and the store.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from . import analyzers as analyzer_plugins
from . import image as image_plugins
from . import isa as isa_plugins
from . import native
from . import toolchains as toolchain_plugins
from . import fsmemo, timing
from .ledger.store import Store

_core = native.core()
CONFIG_NAME = "decompanion.toml"
ConfigError = _core.ConfigError


@dataclass(frozen=True)
class Target:
    name: str
    path: Path
    sha256: str
    image: str | None = None   # the image-format plugin (None: no format declared and several registered)
    legacy: bool = False       # read from the single-table [target] form
    toolchain: tuple = ()      # ((key, value), ...) of the toolchain keys the target table declares itself
    archives: tuple | None = None   # the target's own library archives (strings as written), else None
    isa: str | None = None     # the instruction-set plugin as declared (None: the image's machine type decides)
    reasons: tuple = ()        # ((key, reason), ...) the target table gives for its own declarations


def target_name_of(path) -> str:
    """The default name of a target: the binary's stem, lower case, reduced to [a-z0-9_-]."""
    return _core.config_target_name_of(str(path))


def is_target_name(name: str) -> bool:
    return _core.config_is_target_name(name)


def config_targets(root, text: str) -> list[tuple[str, str]]:
    """(name, path) of every target a configuration's text declares."""
    return _core.config_targets(str(root), text)


class Project:
    def __init__(self, root: Path | None = None, target: str | None = None):
        self.core = _core.Project(None if root is None else str(root), target, native.source_hash())
        self.root = Path(self.core.root)
        self.config_path = self.root / CONFIG_NAME
        self.cfg = self.core.cfg
        self.targets = [Target(n, Path(p), sha, img, legacy, tuple(tc), tuple(a) if a is not None else None, isa, tuple(r))
                        for n, p, sha, img, legacy, tc, a, isa, r in self.core.targets()]
        self.target_name = self.core.target_name
        tc = self.cfg.get("toolchain") or {}
        self.toolchain = toolchain_plugins.TOOLCHAINS[self.core.toolchain_key()](self.expand(tc["root"]) if tc.get("root") else None, tc)
        self.build_dir = self.root / "build"
        fsmemo.attach(self.root)

    def expand(self, s: str) -> Path:
        return Path(self.core.expand(s))

    # ------------------------------------------------------------------ targets
    def target(self, name: str | None = None) -> Target:
        """The named target; None: the current one."""
        name = name or self.target_name
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
        """The main checkout's build directory when this checkout is a worktree (.dcp/main_store), else None."""
        d = self.core.main_build_dir()
        return Path(d) if d is not None else None

    def reason(self, table: str, key: str) -> str:
        """The reason a table of the configuration gives for one of its keys ('' when none)."""
        return self.core.reason(table, key)

    # ------------------------------------------------------------------ objects
    @cached_property
    def image(self):
        t = self.target()
        fmt = image_plugins.FORMATS.get(t.image)
        if fmt is None:
            raise ConfigError(f"target {t.name}: unknown image format {t.image!r} (known: {', '.join(image_plugins.FORMATS)})")
        if not t.path.exists():
            raise ConfigError(f"target {t.name}: {t.path} does not exist")
        img = fmt(t.path)
        if t.sha256 and img.sha256 != t.sha256:
            raise ConfigError(f"target {t.name}: {t.path} has sha256 {img.sha256}, the declared one is {t.sha256}")
        return img

    @property
    def isa_name(self) -> str | None:
        """The current target's instruction set: its `isa` key, else what the image's machine type implies."""
        return self.target().isa or self.image.default_isa

    @cached_property
    def isa(self):
        """The current target's instruction-set plugin (isa/)."""
        key = self.isa_name
        plugin = isa_plugins.get(key) if key else None
        if plugin is None:
            raise ConfigError(f"target {self.target_name}: unknown instruction set {key!r} (known: {', '.join(isa_plugins.ISAS)}); "
                              f"declare isa = ... in its [[target]] table")
        return plugin

    @cached_property
    def analyzer(self):
        """The analyzer of [analyzer] plugin = ... (the core's analyzers.rs; default: ghidra)."""
        cfg = self.cfg.get("analyzer") or {}
        key = cfg.get("plugin") or analyzer_plugins.DEFAULT
        if key not in analyzer_plugins.ANALYZERS:
            raise ConfigError(f"unknown analyzer plugin {key!r} (known: {', '.join(analyzer_plugins.ANALYZERS)}); "
                              f"name one with [analyzer] plugin = ...")
        return analyzer_plugins.Analyzer(self, key)

    def image_of(self, name: str):
        """The image of any target (the current one's is `image`); checked against its declared sha256."""
        if name == self.target_name:
            return self.image
        cache = self.__dict__.setdefault("_images", {})
        if name not in cache:
            cache[name] = Project(self.root, name).image
        return cache[name]

    @cached_property
    def store(self) -> Store:
        main = self.main_build_dir()
        overlay = main / f"{self.target_name}.sqlite" if main is not None else None
        return Store.open(self.store_path(), overlay_of=overlay)

    def lib_archives_of(self, name: str | None = None) -> list[Path]:
        """The library archives of a target: its own `archives` list, else the project's [libs] archives."""
        return [Path(p) for p in self.core.lib_archives(name)]

    @cached_property
    def lib_archives(self) -> list[Path]:
        """The current target's library archives."""
        return self.lib_archives_of()

    def toolchain_decl_for(self, name: str | None = None) -> dict:
        """The toolchain declaration of a target: plugin, root, compiler, linker, cflags; `from` names where each
        came from (target | toolchain | missing), `reasons` the reason of each declared key."""
        return self.core.toolchain_decl(name)

    def archives_decl_for(self, name: str | None = None) -> dict:
        """The library-archive declaration of a target: `archives` (as written, None when nothing declares any),
        `from` (target | libs | missing) and `reason`."""
        return self.core.archives_decl(name)

    def waiting(self, name: str) -> tuple[str, ...]:
        """The obligations (obligations.py) an external input waits on: absent until a human declares it."""
        return tuple(self.core.waiting(name))

    def waiting_for(self, inputs) -> tuple[str, ...]:
        """Every obligation the given inputs wait on, in order, once."""
        return tuple(self.core.waiting_for(list(inputs)))

    @property
    def toolchain_decl(self) -> dict:
        """The current target's toolchain declaration (toolchain_decl_for)."""
        return self.toolchain_decl_for()

    # ------------------------------------------------------------------ inputs
    def input_hash(self, name: str) -> str:
        """The content hash of a named input (the core's: project.rs; the source scan's digest is the front end's)."""
        with timing.phase(f"hash.{name}"):
            return self.core.input_hash(name)

    def forget_input(self, name: str):
        """Drop a memoised input hash (after a command changed the input, e.g. the analyzer's export)."""
        self.core.forget_input(name)

    def input(self, name: str):
        if name == "image":
            return self.image
        if name == "config":
            return self.cfg
        if name == "libs":
            return self.lib_archives
        if name == "archives":
            return [] if self.waiting("libs") else self.lib_archives
        if name == "decl":
            return sorted((self.root / "decl").glob("*.dcl")) if (self.root / "decl").exists() else []
        if name == "src":
            return self.root
        if name == "scan":
            from .ledger import srcscan
            return srcscan.scan(self.root, self.input_hash("src"))
        if name == "drafts":
            from .ledger import drafts
            return drafts.entries(self.store)
        if name == "toolchain":
            return self.toolchain_decl
        if name == "targets":
            return [{"name": t.name, "path": t.path.as_posix(), "sha256": t.sha256, "image": t.image} for t in self.targets]
        if name == "objects":
            return self.store.tus()
        if name == "baseline":
            p = self.root / "ledger" / "grades.tsv"
            return p.read_text() if p.exists() else ""
        if name == "probe":
            return self.store.meta_json("probe")
        if name == "lint":
            m = self.store.meta_json("lint")
            # a lint of an older decompanion (calls without their lines) counts as none: `dcp lint` again
            if m and any(isinstance(c, str) for cs in m.get("calls", {}).values() for c in cs):
                return None
            return m
        raise ConfigError(f"unknown input {name!r}")
