"""`dcp init DIR TARGET`: create a target project around one binary.

The project is a git repository of its own that depends on decompanion. It holds the typed state (sources,
decl/, decompanion.toml, names.log, claims.log, ledger/grades.tsv) and nothing derived (build/ is ignored).
The original binary is referenced by path and pinned by sha256; it is never copied into the repository.
The image format is the registered one that reads the binary, the instruction set the one its machine type
implies (computed, not decisions). Init declares nothing: the toolchain, the library archives and the analyzer
are obligations (obligations.py) that `dcp status` names with their evidence once `dcp setup` ran, resolved by
`dcp toolchain declare`, `dcp libs declare` and `dcp analyzer declare`, each with a reason. The [analyzer]
table holds the plugin this machine has (ghidra when found, else none) until it is confirmed. The decompanion
skills (skills/ of this repository) are installed into .claude/skills/ (`dcp skills
install` updates them in an existing project).
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from . import image as image_plugins

CONFIG = '''# decompanion target project: {name}
# Everything here is typed state; `dcp` derives the rest into build/ (ignored).
#
# Init declares nothing. Every decision of the decompilation is an obligation `dcp status` names when it is due,
# with the evidence and the command that resolves it: `dcp toolchain declare compiler=... linker=... root=...
# cflags=... --why "..."`, `dcp libs declare ARCHIVE... --why "..."`, `dcp analyzer declare ... --why "..."`.
# The declarations land here with their reasons (reason.<key> = "...").

# The binaries built from this codebase; the first is the default target (`--target NAME` selects another,
# `dcp target add NAME PATH` adds one). Each target has its own store, build/<name>.sqlite, and its own
# toolchain declaration (compiler, linker, cflags, archives). name, path, sha256, image and isa are computed
# from the file.
{target_block}
[sources]
roots = ["src"]
include = ["include"]

[analyzer]
# The third-party analyzer `dcp setup` runs for a draft of every function (src/decompanion/analyzers/): "ghidra"
# (headless; root, java_home, timeout = seconds per function), "rea" (file = saved batch_decompile results),
# "none" (dcp draft writes @rough skeletons from the disassembly). Its function starts are declarations.
# Written by `dcp init` from what this machine has; an obligation until `dcp analyzer declare` confirms it.
{analyzer}
'''


def toml_str(s: str) -> str:
    """A TOML basic string."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def target_block(name: str, path: Path, sha: str, image: str, isa: str | None) -> list[str]:
    """The lines of one [[target]] table: what the file itself gives (no declaration)."""
    return ["[[target]]", f"name = {toml_str(name)}", f"path = {toml_str(path.as_posix())}", f"sha256 = {toml_str(sha)}",
            f"image = {toml_str(image)}", *([f"isa = {toml_str(isa)}"] if isa else [])]


def open_target(path: Path):
    """(image format key, image) of a binary: the first registered format that reads it."""
    try:
        return image_plugins.open_image(path)
    except ValueError as ex:
        raise SystemExit(str(ex))


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


def analyzer_lines() -> list[str]:
    """The [analyzer] keys of a new project: the default analyzer with the installation it finds, else none."""
    from . import analyzers
    cls = analyzers.get(None)
    inst = cls({}, None).available()
    if not inst.ok:
        return [f"# {cls.key}: {inst.reason}", 'plugin = "none"']
    out = [f"plugin = {toml_str(cls.key)}"]
    for k in ("root", "java_home"):
        v = inst.detail.get(k)
        if v is not None:
            out.append(f"{k} = {toml_str(Path(v).as_posix())}")
    return out

def init_project(dir_: Path, target: Path, name: str | None = None, target_name: str | None = None):
    """Create the project around one binary. Declares nothing (module docstring)."""
    from .config import TARGET_NAME, target_name_of
    dir_ = Path(dir_).resolve()
    target = Path(target).resolve()
    if not target.exists():
        raise SystemExit(f"target {target} does not exist")
    name = name or dir_.name
    tname = target_name or target_name_of(target)
    if not TARGET_NAME.match(tname):
        raise SystemExit(f"target name {tname!r} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)")
    fmt, img = open_target(target)
    isa = img.default_isa
    if isa is None:
        raise SystemExit(f"{target}: machine type {img.machine:#x} implies no known instruction set")
    sha = hashlib.sha256(target.read_bytes()).hexdigest()
    dir_.mkdir(parents=True, exist_ok=True)
    for sub in ("decl", "src", "include", "ledger", "notes", "libs", ".claude/skills"):
        (dir_ / sub).mkdir(parents=True, exist_ok=True)
    dcp_path = Path(__file__).resolve().parents[2]
    analyzer = analyzer_lines()
    files = {
        "decompanion.toml": CONFIG.format(name=name, analyzer="\n".join(analyzer),
                                          target_block="\n".join(target_block(tname, target, sha, fmt, isa)) + "\n"),
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
        "README.md": f"# {name}\n\nA decompanion target project for `{target.name}`. Run `uv run dcp setup`, then follow `uv run dcp status`.\n",
    }
    for rel, text in files.items():
        p = dir_ / rel
        if not p.exists():
            p.write_text(text, newline="\n")
    if not (dir_ / ".git").exists():
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dir_, check=True)
    from .cli_session import install_skills
    skills = install_skills(dir_)
    print(f"initialised {dir_} for {target.name} as target {tname} (sha256 {sha[:16]})")
    print(f"  computed: image={fmt} isa={isa}; declared: nothing (toolchain, libraries, analyzer: the obligations of dcp status)")
    print("  analyzer (to confirm): " + "  ".join(l for l in analyzer if not l.startswith("#")))
    if skills:
        print(f"  skills: {', '.join(sorted({s.split('/')[2] for s in skills}))} in .claude/skills/ (dcp skills install updates them)")
    print("next: cd there, uv sync, uv run dcp setup (it prints the open obligations; uv run dcp status repeats them)")


def add_target(root: Path, name: str, path: Path) -> str:
    """Append a [[target]] table to decompanion.toml (after the last one), rewriting the single-table [target]
    form of milestone 1 into the list form first. Like `dcp init` it declares nothing: the new target's
    compiler, linker, cflags and archives are its obligations (inherited from [toolchain] / [libs] where those
    hold defaults). Returns the new table's text."""
    import tomllib

    from .config import CONFIG_NAME, TARGET_NAME, parse_targets, target_name_of
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
    block = ["", *target_block(name, path, sha, fmt, isa)]
    lines[end:end] = block
    cfg_path.write_text("\n".join(lines), newline="\n")
    tomllib.loads(cfg_path.read_text())         # still valid
    return "\n".join(block[1:])
