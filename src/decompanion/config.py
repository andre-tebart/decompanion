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
                 (the third-party analyzer `dcp setup` runs for drafts; default: ghidra; plugin "rea" reads
                 file = "..." (saved batch_decompile results), "none" exports nothing)

The plugins (image format, toolchain, object format, instruction set, analyzer) come from the registries of
their packages; this module names none of them.

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

from . import analyzers as analyzer_plugins
from . import image as image_plugins
from . import isa as isa_plugins
from . import objfmt as objfmt_plugins
from . import toolchains as toolchain_plugins
from . import fsmemo, timing
from .ledger.fact import canonical
from .ledger.store import Store, file_hash, sha256

CONFIG_NAME = "decompanion.toml"
PLUGIN_PACKAGES = (image_plugins, toolchain_plugins, objfmt_plugins, isa_plugins)
TARGET_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class ConfigError(RuntimeError):
    pass


TOOLCHAIN_KEYS = ("compiler", "linker", "cflags")
TARGET_KEYS = ("name", "path", "sha256", "image", "isa", "archives", *TOOLCHAIN_KEYS, "reason")
REASON_KEYS = (*TOOLCHAIN_KEYS, "archives", "root", "plugin")    # the keys a `reason.<key>` may name


def reason_of(table: dict, key: str) -> str:
    """The reason a table gives for one of its keys: `reason.<key>`, or the older form `reason = "..."` (one
    reason for every key of the table); '' when it gives none."""
    r = (table or {}).get("reason")
    if isinstance(r, dict):
        r = r.get(key, "")
    return str(r or "").strip()


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
        unknown = sorted(set(tab) - set(TARGET_KEYS))
        if unknown:
            raise ConfigError(f"{CONFIG_NAME}: target {name!r} has unknown keys {', '.join(unknown)} (known: {', '.join(TARGET_KEYS)})")
        archives = tab.get("archives")
        if archives is not None and not (isinstance(archives, list) and all(isinstance(a, str) for a in archives)):
            raise ConfigError(f"{CONFIG_NAME}: target {name!r}: archives is not a list of paths")
        r = tab.get("reason")
        if isinstance(r, dict):
            bad = sorted(set(r) - set(REASON_KEYS))
            if bad:
                raise ConfigError(f"{CONFIG_NAME}: target {name!r}: reason.{bad[0]} names no declaration (known: {', '.join(REASON_KEYS)})")
        elif r is not None and not isinstance(r, str):
            raise ConfigError(f"{CONFIG_NAME}: target {name!r}: reason is neither a string nor reason.<key> = ...")
        tc = tuple((k, tuple(tab[k]) if isinstance(tab[k], list) else tab[k]) for k in TOOLCHAIN_KEYS if k in tab)
        reasons = tuple((k, reason_of(tab, k)) for k in (*TOOLCHAIN_KEYS, "archives") if reason_of(tab, k))
        out.append(Target(name, path, tab.get("sha256", ""), tab.get("image") or image_plugins.default_key(), legacy, tc,
                          tuple(archives) if archives is not None else None, tab.get("isa"), reasons))
    if not out:
        raise ConfigError(f"{CONFIG_NAME}: the [[target]] list is empty")
    return out


def toolchain_plugin_key(tc: dict) -> str | None:
    """[toolchain] plugin, else the only registered toolchain plugin."""
    return tc.get("plugin") or toolchain_plugins.default_key()


_plugins_digest: str | None = None


def plugins_hash(selection: str) -> str:
    """The hash of the plugin code every rule reads through the seams (image, toolchain, object format and
    instruction-set packages, every .py file) and of the selection: editing a plugin reruns the rules."""
    global _plugins_digest
    if _plugins_digest is None:
        h = hashlib.sha256()
        for pkg in PLUGIN_PACKAGES:
            d = Path(pkg.__file__).parent
            for p in sorted(d.rglob("*.py")):
                h.update(p.relative_to(d.parent).as_posix().encode() + b"\0" + p.read_bytes())
        _plugins_digest = h.hexdigest()
    return sha256(_plugins_digest, selection)


class Project:
    def __init__(self, root: Path | None = None, target: str | None = None):
        self.root = find_root(root) if root is None or not (Path(root) / CONFIG_NAME).exists() else Path(root).resolve()
        self.config_path = self.root / CONFIG_NAME
        self.cfg = tomllib.loads(self.config_path.read_text())
        self.targets = parse_targets(self.cfg, self.expand)
        self.target_name = self.target(target).name     # the current target (default: the first)
        tc = self.cfg.get("toolchain") or {}
        key = toolchain_plugin_key(tc)
        plugin = toolchain_plugins.TOOLCHAINS.get(key)
        if plugin is None:
            raise ConfigError(f"unknown toolchain plugin {key!r} (known: {', '.join(toolchain_plugins.TOOLCHAINS)}); "
                              f"name one with [toolchain] plugin = ...")
        self.toolchain = plugin(self.expand(tc["root"]) if tc.get("root") else None, tc)
        self.build_dir = self.root / "build"
        self._hashes: dict[str, str] = {}
        fsmemo.attach(self.root)

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
        t = self.target()
        return t.isa or self.image.default_isa

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
        """The analyzer plugin of [analyzer] plugin = ... (analyzers/; default: ghidra), with its table."""
        cfg = self.cfg.get("analyzer") or {}
        key = cfg.get("plugin") or analyzer_plugins.DEFAULT
        plugin = analyzer_plugins.get(key)
        if plugin is None:
            raise ConfigError(f"unknown analyzer plugin {key!r} (known: {', '.join(analyzer_plugins.ANALYZERS)}); "
                              f"name one with [analyzer] plugin = ...")
        return plugin(cfg, self.expand)

    @cached_property
    def objfmt(self):
        """The object-format plugin of the toolchain's objects and archives (objfmt/)."""
        plugin = objfmt_plugins.get(self.toolchain.object_format)
        if plugin is None:
            raise ConfigError(f"toolchain {self.toolchain.key}: unknown object format {self.toolchain.object_format!r}")
        return plugin

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
        t = self.target(name)
        own = t.archives is not None
        libs = self.archives_decl_for(name)["archives"] or []
        out = []
        for s in libs:
            p = self.expand(s)
            if not p.exists():
                where = f"target {t.name} archives" if own else "[libs] archives"
                raise ConfigError(f"{where}: {p} does not exist")
            out.append(p)
        return out

    @cached_property
    def lib_archives(self) -> list[Path]:
        """The current target's library archives."""
        return self.lib_archives_of()

    def toolchain_decl_for(self, name: str | None = None) -> dict:
        """The toolchain declaration of a target: plugin and root from [toolchain]; compiler, linker and cflags
        from the target's own table, else the [toolchain] defaults. `from` names where each came from (target |
        toolchain | missing), `reasons` the reason of each declared key (from the same table; '' when it gives
        none)."""
        tc = self.cfg.get("toolchain") or {}
        t = self.target(name)
        own, own_reasons = dict(t.toolchain), dict(t.reasons)
        out = {"plugin": toolchain_plugin_key(tc), "root": tc.get("root", "")}
        src = {"root": "toolchain" if tc.get("root") else "missing"}
        reasons = {"root": reason_of(tc, "root") if tc.get("root") else ""}
        for k in TOOLCHAIN_KEYS:
            if k in own:
                v, src[k], reasons[k] = own[k], "target", own_reasons.get(k, "")
            elif k in tc:
                v, src[k], reasons[k] = tc[k], "toolchain", reason_of(tc, k)
            else:
                v, src[k], reasons[k] = ([] if k == "cflags" else ""), "missing", ""
            out[k] = list(v) if isinstance(v, (list, tuple)) else v
        out["from"] = src
        out["reasons"] = reasons
        return out

    def archives_decl_for(self, name: str | None = None) -> dict:
        """The library-archive declaration of a target: `archives` (the strings as written, None when nothing
        declares any), `from` (target | libs | missing) and `reason`."""
        t = self.target(name)
        if t.archives is not None:
            return {"archives": list(t.archives), "from": "target", "reason": dict(t.reasons).get("archives", "")}
        libs = self.cfg.get("libs") or {}
        if "archives" in libs:
            return {"archives": list(libs["archives"] or []), "from": "libs", "reason": reason_of(libs, "archives")}
        return {"archives": None, "from": "missing", "reason": ""}

    def waiting(self, name: str) -> tuple[str, ...]:
        """The obligations (obligations.py) an external input waits on: absent until a human declares it. A rule
        reading a waiting input does not run (rules/engine.py); `libs` waits for the archives (and for the
        toolchain root when they are spelled under it), `toolchain` for the compiler and linker builds."""
        cache = self.__dict__.setdefault("_waiting", {})
        if name in cache:
            return cache[name]
        out: tuple[str, ...] = ()
        if name == "libs":
            d = self.archives_decl_for()
            if d["archives"] is None:
                out = ("libs.archives",)
            elif not (self.cfg.get("toolchain") or {}).get("root") and any("{toolchain.root}" in a for a in d["archives"]):
                out = ("toolchain.root",)
        elif name == "toolchain":
            d = self.toolchain_decl
            out = tuple(f"toolchain.{k}" for k in ("compiler", "linker") if not d[k])
        cache[name] = out
        return out

    def waiting_for(self, inputs) -> tuple[str, ...]:
        """Every obligation the given inputs wait on, in order, once."""
        return tuple(dict.fromkeys(w for i in inputs for w in self.waiting(i)))

    @property
    def toolchain_decl(self) -> dict:
        """The current target's toolchain declaration (toolchain_decl_for)."""
        return self.toolchain_decl_for()

    # ------------------------------------------------------------------ inputs
    def input_hash(self, name: str) -> str:
        if name in self._hashes:
            return self._hashes[name]
        with timing.phase(f"hash.{name}"):
            h = self._input_hash(name)
        self._hashes[name] = h
        return h

    def _input_hash(self, name: str) -> str:
        if name == "image":
            h = file_hash(self.image_path)
        elif name == "config":
            h = file_hash(self.config_path)
        elif name in ("libs", "archives"):
            # archives: the declared archives or none while `libs` waits (S.rich reads it, the Rich candidates
            # need no archive; their archive_objects counts do)
            libs = [] if self.waiting("libs") else self.lib_archives
            h = hashlib.sha256(b"".join(f"{p.name}:{file_hash(p)}\n".encode() for p in libs)).hexdigest()
        elif name == "decl":
            h = self.tree_hash([self.root / "decl"], ("*.dcl",))
        elif name == "src":
            h = self.tree_hash([self.root / "src", self.root / "include"], ("*.c", "*.h"))
        elif name == "scan":
            from .ledger import srcscan
            h = srcscan.scan(self.root, self.input_hash("src")).digest()
        elif name == "drafts":
            from .ledger import drafts
            h = drafts.input_hash(self.store)
        elif name == "toolchain":
            h = sha256(canonical(self.toolchain_decl))
        elif name == "targets":
            h = sha256(canonical(self.input("targets")))
        elif name == "plugins":
            h = plugins_hash(f"{self.target().image}/{self.toolchain.key}/{self.toolchain.object_format}/{self.target().isa or ''}")
        elif name == "objects":
            h = sha256(self.store.tu_hash(), str(self.toolchain.available()))
        elif name == "baseline":
            p = self.root / "ledger" / "grades.tsv"
            h = file_hash(p) if p.exists() else "none"
        elif name == "probe":
            h = sha256(self.store.meta("probe") or "")
        elif name == "lint":
            h = sha256(self.store.meta("lint") or "")
        else:
            raise ConfigError(f"unknown input {name!r}")
        return h

    def forget_input(self, name: str):
        """Drop a memoised input hash (after a command changed the input, e.g. the analyzer's export)."""
        self._hashes.pop(name, None)
        if name == "src":
            self._hashes.pop("scan", None)            # the source scan's items, of the sources

    @staticmethod
    def tree_hash(dirs: list[Path], patterns: tuple[str, ...]) -> str:
        h = hashlib.sha256()
        for d in dirs:
            if not d.exists():
                continue
            h.update(d.name.encode() + b"\1")
            for rel, p in fsmemo.walk(d, patterns):
                h.update(rel.encode())
                h.update(b"\0")
                h.update(bytes.fromhex(fsmemo.sha256(p)))
        return h.hexdigest()

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
            import json
            m = self.store.meta("probe")
            return json.loads(m) if m else None
        if name == "lint":
            import json
            m = json.loads(self.store.meta("lint") or "null")
            # a lint of an older decompanion (calls without their lines) counts as none: `dcp lint` again
            if m and any(isinstance(c, str) for cs in m.get("calls", {}).values() for c in cs):
                return None
            return m
        raise ConfigError(f"unknown input {name!r}")
