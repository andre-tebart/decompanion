"""`dcp init DIR TARGET`: create a target project around one binary.

The project is a git repository of its own that depends on decompanion. It holds the typed state (sources,
decl/, decompanion.toml, names.log, claims.log, ledger/grades.tsv) and nothing derived (build/ is ignored).
The original binary is referenced by path and pinned by sha256; it is never copied into the repository.
The image format is the registered one that reads the binary, the instruction set the one its machine type
implies; the toolchain plugin's answers pre-fill the rest (its default archives and flags, the Rich-header
pick), each for a human to verify.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from . import image as image_plugins
from . import objfmt as objfmt_plugins
from . import toolchains as toolchain_plugins

CONFIG = '''# decompanion target project: {name}
# Everything here is typed state; `dcp` derives the rest into build/ (ignored).

# The binaries built from this codebase; the first is the default target (`--target NAME` selects another,
# `dcp target add NAME PATH` adds one). Each target has its own store, build/<name>.sqlite, and its own
# toolchain declaration: the compiler and linker builds are picked from the Rich header's candidates (`dcp
# toolchain` lists them; C.toolchain checks the pick), flags are declared until `dcp toolchain probe` proves
# them per unit (milestone 3). A declaration without a reason is a gate error. `archives = [...]` in a target
# replaces the [libs] archives for that target.
{target_block}
[toolchain]
plugin = {plugin}
root = {tc_root}

[libs]
# Archives whose members are placed in the image by S.crt.code (static CRT and SDK libraries); the default of
# every target without its own `archives`.
archives = [{archives}]

[sources]
roots = ["src"]
include = ["include"]
'''


def toml_str(s: str) -> str:
    """A TOML basic string."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def target_block(name: str, path: Path, sha: str, image: str, isa: str | None, compiler: str, linker: str,
                 cflags: list[str], reason: str) -> list[str]:
    """The lines of one [[target]] table."""
    return ["[[target]]", f"name = {toml_str(name)}", f"path = {toml_str(path.as_posix())}", f"sha256 = {toml_str(sha)}",
            f"image = {toml_str(image)}", *([f"isa = {toml_str(isa)}"] if isa else []),
            f"compiler = {toml_str(compiler)}", f"linker = {toml_str(linker)}",
            "cflags = [" + ", ".join(toml_str(c) for c in cflags) + "]", f"reason = {toml_str(reason)}"]


def open_target(path: Path):
    """(image format key, image) of a binary: the first registered format that reads it."""
    try:
        return image_plugins.open_image(path)
    except ValueError as ex:
        raise SystemExit(str(ex))


def prefill(img, toolchain, archives: list[Path], when: str) -> tuple[str, str, str]:
    """(compiler, linker, reason) for a new target: Toolchain.prefill on the image's Rich candidates, with the
    archives' tool stamps (a declaration for a human to verify, not a fact)."""
    entries = img.rich()
    fmt = objfmt_plugins.get(toolchain.object_format)
    stamps = fmt.tool_stamps([a for a in archives if a.exists()]) if fmt is not None else {}
    cands = toolchain.rich_candidates(entries, toolchain.archive_tools(stamps)) if entries else {}
    return toolchain.prefill(cands, when)


GITATTRIBUTES = """# LF and UTF-8 (no BOM) everywhere: the store hashes file contents.
* text=auto eol=lf
*.dll binary
*.exe binary
*.obj binary
*.lib binary
# append-only logs: keep both sides' additions
names.log merge=union
claims.log merge=union
# the grade baseline is promoted on main only
ledger/grades.tsv merge=ours
"""

GITIGNORE = """/build/
.dcp/
__pycache__/
.venv/
"""

PYPROJECT = '''[project]
name = "{name}"
version = "0.0.0"
requires-python = ">=3.15"
dependencies = ["decompanion"]

[tool.uv.sources]
decompanion = {{ path = "{dcp_path}", editable = true }}
'''


TOOLCHAIN_ROOT_MISSING = ("the toolchain root is required: the directory of the toolchain installation the "
                          "binary was built with (VC6: the folder that holds VC98/), e.g. --toolchain-root C:/Tools/MSVC600")


def toolchain_plugin(key: str | None):
    """The toolchain plugin class `key`, else the only registered one."""
    key = key or toolchain_plugins.default_key()
    cls = toolchain_plugins.TOOLCHAINS.get(key) if key else None
    if cls is None:
        raise SystemExit(f"unknown toolchain plugin {key!r} (known: {', '.join(toolchain_plugins.TOOLCHAINS)})")
    return cls


def init_project(dir_: Path, target: Path, toolchain_root: str, name: str | None = None, target_name: str | None = None,
                 toolchain: str | None = None):
    from .config import TARGET_NAME, target_name_of
    if not toolchain_root:
        raise SystemExit(TOOLCHAIN_ROOT_MISSING)
    dir_ = Path(dir_).resolve()
    target = Path(target).resolve()
    if not target.exists():
        raise SystemExit(f"target {target} does not exist")
    name = name or dir_.name
    tname = target_name or target_name_of(target)
    if not TARGET_NAME.match(tname):
        raise SystemExit(f"target name {tname!r} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)")
    toolchain_root = Path(toolchain_root).as_posix()
    fmt, img = open_target(target)
    isa = img.default_isa
    if isa is None:
        raise SystemExit(f"{target}: machine type {img.machine:#x} implies no known instruction set")
    sha = hashlib.sha256(target.read_bytes()).hexdigest()
    tc = toolchain_plugin(toolchain)(Path(toolchain_root), {})
    archives = tc.default_archives()
    cflags = tc.default_cflags()
    compiler, linker, reason = prefill(img, tc, [Path(a.replace("{toolchain.root}", toolchain_root)) for a in archives], "init")
    dir_.mkdir(parents=True, exist_ok=True)
    for sub in ("decl", "src", "include", "ledger", "notes", "libs", ".claude/skills"):
        (dir_ / sub).mkdir(parents=True, exist_ok=True)
    dcp_path = Path(__file__).resolve().parents[2]
    files = {
        "decompanion.toml": CONFIG.format(
            name=name, plugin=toml_str(tc.key), tc_root=toml_str(toolchain_root), archives=", ".join(toml_str(a) for a in archives),
            target_block="\n".join(target_block(tname, target, sha, fmt, isa, compiler, linker, cflags, reason)) + "\n"),
        ".gitattributes": GITATTRIBUTES,
        ".gitignore": GITIGNORE,
        ".editorconfig": "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\n",
        ".python-version": "3.15\n",
        "pyproject.toml": PYPROJECT.format(name=name, dcp_path=dcp_path.as_posix()),
        "decl/text.dcl": "# declarations about the code sections; one fact per line, sorted by address (`dcp decl add` inserts)\n"
                         "# [TARGET:]ADDR[..END] KIND [WORD ...] [key=value ...] -- reason\n",
        "decl/data.dcl": "# declarations about the data sections; one fact per line, sorted by address (`dcp decl add` inserts)\n",
        "names.log": "",
        "claims.log": "",
        "ledger/grades.tsv": "",
        "README.md": f"# {name}\n\nA decompanion target project for `{target.name}`. Run `uv run dcp setup`.\n",
    }
    for rel, text in files.items():
        p = dir_ / rel
        if not p.exists():
            p.write_text(text, newline="\n")
    if not (dir_ / ".git").exists():
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dir_, check=True)
    print(f"initialised {dir_} for {target.name} as target {tname} (sha256 {sha[:16]})")
    print(f"  declared: image={fmt} isa={isa} toolchain={tc.key} compiler={compiler or '-'} linker={linker or '-'} "
          f"cflags={' '.join(cflags) or '-'}  reason={reason!r}")
    print("next: cd there, uv sync, uv run dcp toolchain (verify the declaration), uv run dcp setup")


def add_target(root: Path, name: str, path: Path) -> str:
    """Append a [[target]] table to decompanion.toml (after the last one), rewriting the single-table [target]
    form of milestone 1 into the list form first. The new table's toolchain declaration is pre-filled like `dcp
    init`'s (Toolchain.prefill with the project's [libs] archives), its cflags copied from the default target.
    Returns the new table's text."""
    import tomllib

    from .config import CONFIG_NAME, TARGET_NAME, Project, parse_targets, target_name_of
    cfg_path = Path(root) / CONFIG_NAME
    text = cfg_path.read_text()
    cfg = tomllib.loads(text)
    if not TARGET_NAME.match(name):
        raise SystemExit(f"target name {name!r} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)")
    path = Path(path).resolve()
    if not path.exists():
        raise SystemExit(f"{path} does not exist")
    fmt, img = open_target(path)                 # refuses what no registered image format reads
    isa = img.default_isa
    if isa is None:
        raise SystemExit(f"{path}: machine type {img.machine:#x} implies no known instruction set")
    existing = parse_targets(cfg, lambda s: Path(s))
    if any(t.name == name for t in existing):
        raise SystemExit(f"target {name!r} exists")
    proj = Project(root)
    default = proj.toolchain_decl_for(proj.default_target)
    libs = [proj.expand(a) for a in (cfg.get("libs") or {}).get("archives") or []]
    compiler, linker, reason = prefill(img, proj.toolchain, libs, "target add")
    cflags = list(default.get("cflags") or [])
    reason = reason.replace("; flags assumed;", f"; cflags copied from target {proj.default_target};")
    lines = text.split("\n")
    if isinstance(cfg.get("target"), dict):     # the milestone-1 form: [target] without a name
        i = next(k for k, l in enumerate(lines) if l.strip() == "[target]")
        lines[i] = "[[target]]"
        lines.insert(i + 1, f'name = "{target_name_of(existing[0].path)}"')
    heads = [k for k, l in enumerate(lines) if l.strip() == "[[target]]"]
    end = next((k for k in range(heads[-1] + 1, len(lines)) if lines[k].lstrip().startswith("[")), len(lines))
    while end > heads[-1] + 1 and not lines[end - 1].strip():
        end -= 1
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    block = ["", *target_block(name, path, sha, fmt, isa, compiler, linker, cflags, reason)]
    lines[end:end] = block
    cfg_path.write_text("\n".join(lines), newline="\n")
    tomllib.loads(cfg_path.read_text())         # still valid
    return "\n".join(block[1:])
