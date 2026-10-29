"""`dcp init DIR TARGET`: create a target project around one binary.

The project is a git repository of its own that depends on decompanion. It holds the typed state (sources,
decl/, decompanion.toml, names.log, claims.log, ledger/grades.tsv) and nothing derived (build/ is ignored).
The original binary is referenced by path and pinned by sha256; it is never copied into the repository.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from .image.pe32 import PE32

CONFIG = '''# decompanion target project: {name}
# Everything here is typed state; `dcp` derives the rest into build/ (ignored).

[target]
path = "{target}"
sha256 = "{sha}"
image = "pe32"

[toolchain]
plugin = "vc6"
root = "{tc_root}"
# The compiler and linker builds the Rich header names (S.rich); flags are declared until `dcp toolchain probe`
# proves them per unit (milestone 3). A declaration without a reason is a gate error (C.toolchain).
compiler = "{compiler}"
linker = "{linker}"
cflags = ["/O2", "/Gy"]
reason = "{reason}"

[libs]
# Archives whose members are placed in the image by S.crt.code (static CRT and SDK libraries).
archives = ["{{toolchain.root}}/VC98/Lib/LIBC.LIB"]

[sources]
roots = ["src"]
include = ["include"]
'''

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

GITIGNORE = """build/
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


def init_project(dir_: Path, target: Path, toolchain_root: str, name: str | None = None):
    dir_ = Path(dir_).resolve()
    target = Path(target).resolve()
    if not target.exists():
        raise SystemExit(f"target {target} does not exist")
    name = name or dir_.name
    toolchain_root = Path(toolchain_root).as_posix()
    img = PE32(target)
    sha = hashlib.sha256(target.read_bytes()).hexdigest()
    compiler, linker, reason = "", "", "declared at init: builds from the Rich header, flags assumed like the sibling exe"
    rich = img.rich()
    if rich:
        from .toolchains.vc6 import rich as richtab
        comps = [(b, c, p) for p, b, c in rich if richtab.product(p).family == "compiler"]
        links = [(b, c, p) for p, b, c in rich if richtab.product(p).family == "linker"]
        if comps:
            b = max(comps)[0]
            compiler = f"cl 12.00.{b}"
        if links:
            linker = f"link 6.00.{max(links)[0]}"
    dir_.mkdir(parents=True, exist_ok=True)
    for sub in ("decl", "src", "include", "ledger", "notes", "libs", ".claude/skills"):
        (dir_ / sub).mkdir(parents=True, exist_ok=True)
    dcp_path = Path(__file__).resolve().parents[2]
    files = {
        "decompanion.toml": CONFIG.format(name=name, target=target.as_posix(), sha=sha, tc_root=toolchain_root,
                                          compiler=compiler, linker=linker, reason=reason),
        ".gitattributes": GITATTRIBUTES,
        ".gitignore": GITIGNORE,
        ".editorconfig": "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\n",
        ".python-version": "3.15\n",
        "pyproject.toml": PYPROJECT.format(name=name, dcp_path=dcp_path.as_posix()),
        "decl/text.dcl": "# declarations about the code sections; one fact per line, sorted by address\n# ADDR[..END] KIND [k=v ...] -- reason\n",
        "decl/data.dcl": "# declarations about the data sections; one fact per line, sorted by address\n",
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
    print(f"initialised {dir_} for {target.name} (sha256 {sha[:16]}, {compiler or 'no rich header'}); next: cd there, uv sync, uv run dcp setup")
