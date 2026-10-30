"""Edits of the typed state the layout commands make (dcp unit new / join / rename, dcp draft, dcp rename): the
whole-word rename over src/ and include/, the append-only names.log, include lines and declaration blocks in a
unit's head region (the lines before its first function: head_end) and the unit headers, a function inserted
into its unit's file, `git mv`. Every edit writes UTF-8 with LF.

names.log (plan section 4): one line per rename event, appended, never rewritten (merge=union):

    <ts> <addr|-> <kind> <old> -> <new> by:<checkout> why:<text>

ts is the local time in ISO form to the second; addr the target address the name belongs to (`-` for a unit, a
type or a name without one); kind one of func, data, ident, unit; checkout `main` or the worktree's name.
"""
from __future__ import annotations

import bisect
import datetime
import re
import subprocess
from pathlib import Path

from .. import fsmemo

IDENT = re.compile(r"^[A-Za-z_]\w*$")
TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)
DCP_BLOCK = "/* dcp draft: declarations of functions and data the unit uses that no included header declares */"


class EditError(RuntimeError):
    pass


def sources(root: Path) -> list[Path]:
    """Every .c / .h file of src/ and include/."""
    out = []
    for d in ("src", "include"):
        base = Path(root) / d
        if base.exists():
            out += sorted((Path(p) for _, p in fsmemo.walk(base, ("*.c", "*.h")) if p[-2:] in (".c", ".h")),
                          key=lambda p: str(p).lower())
    return out


def write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, newline="\n")
    fsmemo.wrote(path)


def code_words(text: str) -> set[str]:
    """The identifiers of a C text outside comments and string literals."""
    code = TOKEN.sub(lambda m: " " * len(m.group(0)) if not m.group(0).startswith(("/*", "//")) else " ", text)
    return set(re.findall(r"\b[A-Za-z_]\w*\b", code))


def uses(root: Path, name: str) -> list[tuple[str, int]]:
    """(file, line) of every whole-word occurrence of name in src/ and include/ (comments included)."""
    pat = re.compile(rf"\b{re.escape(name)}\b")
    out = []
    for p in sources(root):
        text = fsmemo.read_text(p)
        if not pat.search(text):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                out.append((p.relative_to(root).as_posix(), i))
    return out


STRINGS = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|^[ \t]*#[ \t]*include\b[^\n]*', re.M)


def replace_words(text: str, mapping: dict[str, str], skip: set | None = None) -> tuple[str, int]:
    """Every whole-word occurrence of an old name in code and comments replaced by its new one; string and
    character literals and #include lines are left alone (a unit's header may carry the old spelling of a
    name), and the occurrences at the (line, col) positions of `skip` (another symbol of that name: a local, a
    parameter, a field). Returns (text, replacements)."""
    pat = re.compile(r"\b(" + "|".join(sorted(map(re.escape, mapping), key=len, reverse=True)) + r")\b")
    out, pos, n = [], 0, 0
    starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"] if skip else None

    def sub(m, base):
        nonlocal n
        if skip:
            at = base + m.start()
            line = bisect.bisect_right(starts, at)
            if (line, at - starts[line - 1] + 1) in skip:
                return m.group(0)
        n += 1
        return mapping[m.group(1)]
    for m in STRINGS.finditer(text):
        b = pos
        out.append(pat.sub(lambda x: sub(x, b), text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    b = pos
    out.append(pat.sub(lambda x: sub(x, b), text[pos:]))
    return "".join(out), n


def rename_words(root: Path, mapping: dict[str, str], dry: bool = False, skip: dict | None = None) -> dict[str, int]:
    """Replace every whole-word occurrence of each old name by its new one in one pass over src/ and include/
    (code and comments: a name in an address comment or a description follows the rename; not inside string
    literals or #include lines; not at the positions skip[file] gives: srcscan.local_refs, the occurrences
    that are another symbol). Returns {file: replacements}; `dry` counts them and writes nothing."""
    if not mapping:
        return {}
    out = {}
    any_old = re.compile("|".join(map(re.escape, mapping)))     # a file without any old name is not parsed
    for p in sources(root):
        text = fsmemo.read_text(p)
        if not any_old.search(text):
            continue
        new, n = replace_words(text, mapping, (skip or {}).get(p.relative_to(root).as_posix()))
        if n:
            if not dry:
                write(p, new)
            out[p.relative_to(root).as_posix()] = n
    return out


def words_with_prefix(root: Path, prefix: str) -> set[str]:
    """Every identifier of src/ and include/ that starts with prefix (prefix itself included when it occurs)."""
    pat = re.compile(rf"\b{re.escape(prefix)}\w*")
    out = set()
    for p in sources(root):
        text = fsmemo.read_text(p)
        if prefix in text:
            out |= set(pat.findall(text))
    return out


_blank: dict[tuple[str, str], str] = {}     # (file, sha256) -> its text with comments, strings and includes blanked


def code_uses(root: Path, name: str, skip: dict | None = None) -> list[tuple[str, int]]:
    """(file, line) of every occurrence of name as an identifier of the code (comments, strings and #include
    lines blanked), but those at the (line, col) positions skip[file] gives (srcscan.local_refs: a local, a
    parameter, a field of that name, which a file-scope symbol does not collide with): what a rename to `name`
    would collide with."""
    pat = re.compile(rf"\b{re.escape(name)}\b")
    out = []
    for p in sources(root):
        text = fsmemo.read_text(p)
        if not pat.search(text):
            continue
        key = (str(p), fsmemo.sha256(p))
        blank = _blank.get(key)
        if blank is None:
            if len(_blank) > 20000:
                _blank.clear()
            blank = TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
            blank = _blank[key] = re.sub(r"(?m)^[ \t]*#[ \t]*include\b[^\n]*", "", blank)
        rel = p.relative_to(root).as_posix()
        local = (skip or {}).get(rel, set())
        for i, line in enumerate(blank.splitlines(), 1):
            if any((i, m.start() + 1) not in local for m in pat.finditer(line)):
                out.append((rel, i))
    return out


def checkout_name(root: Path) -> str:
    marker = Path(root) / ".dcp" / "main_store"
    return Path(root).name if marker.exists() else "main"


def log_names(root: Path, events: list[tuple[int | None, str, str, str]], why: str):
    """Append one names.log line per (addr, kind, old, new)."""
    if not events:
        return
    ts = datetime.datetime.now().replace(microsecond=0).isoformat()
    by = checkout_name(root)
    why = " ".join(why.split())
    lines = [f"{ts} {f'{a:#010x}' if a is not None else '-'} {k} {o} -> {n} by:{by} why:{why}\n" for a, k, o, n in events]
    path = Path(root) / "names.log"
    old = path.read_text() if path.exists() else ""
    if old and not old.endswith("\n"):
        old += "\n"
    write(path, old + "".join(lines))


def git(root: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)


def tracked(root: Path, path: Path) -> bool:
    r = git(root, "ls-files", "--error-unmatch", Path(path).relative_to(root).as_posix())
    return r.returncode == 0


def move(root: Path, src: Path, dst: Path):
    """git mv when the file is tracked, else a plain rename."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if (Path(root) / ".git").exists() and tracked(root, src):
        r = git(root, "mv", Path(src).relative_to(root).as_posix(), Path(dst).relative_to(root).as_posix())
        if r.returncode != 0:
            raise EditError(f"git mv {src} {dst}: {r.stderr.strip()}")
    else:
        Path(src).rename(dst)
    fsmemo.wrote(dst)


def remove(root: Path, path: Path):
    """git rm (tracked) or delete a file."""
    if not Path(path).exists():
        return
    if (Path(root) / ".git").exists() and tracked(root, path):
        r = git(root, "rm", "-q", "-f", Path(path).relative_to(root).as_posix())
        if r.returncode != 0:
            raise EditError(f"git rm {path}: {r.stderr.strip()}")
    if Path(path).exists():
        Path(path).unlink()
    fsmemo.wrote(path)


# ------------------------------------------------------------------------------------------------ head region / headers
def head_end(root: Path, rel: str) -> int:
    """The 0-based line index where a unit file's head region ends: its first function's address comment (else
    its first definition; the file's end without one), from the scan. An insertion into the head only moves the
    end down, so an end computed before a series of head edits stays inside the head."""
    from ..ledger import srcscan
    sc = srcscan.scan(Path(root))
    m = sc.models.get(rel, srcscan.EMPTY)
    lines = [f.comment_line for f in sc.functions if f.file == rel] + [d[0] for d in m["defs"]]
    p = Path(root) / rel
    n = fsmemo.read_text(p).count("\n") + 1 if p.exists() else 0
    return min(lines, default=n + 1) - 1


def insert_function(path: Path, block: str, before: int | None):
    """Insert a function's text (its address comment first) into a unit's file before the line `before`
    (1-based: the next function's address comment), else at the end, a blank line between it and its
    neighbours."""
    text = path.read_text() if path.exists() else ""
    lines = text.rstrip("\n").split("\n") if text.strip() else []
    new = block.rstrip("\n").split("\n")
    if before is None or before > len(lines):
        lines += [""] + new
    else:
        lines[before - 1:before - 1] = new + [""]
    write(path, "\n".join(lines) + "\n")


def block_line(lines: list[str]) -> int | None:
    """The index of the dcp declaration block's heading line."""
    return next((i for i, l in enumerate(lines) if l == DCP_BLOCK), None)


def guard(unit: str) -> str:
    return re.sub(r"\W", "_", unit).upper() + "_H"


def c_name(unit: str) -> str:
    """The unit name as part of a C identifier (`.` and `-` become `_`)."""
    return re.sub(r"\W", "_", unit)


def ensure_include(path: Path, line: str, end: int | None = None) -> bool:
    """Add an #include line after the last #include of the file's first `end` lines (a unit's head region:
    head_end; the whole file without), else after its leading comment; False when the file has it already."""
    text = path.read_text() if path.exists() else ""
    if line.strip() in (l.strip() for l in text.splitlines()):
        return False
    lines = text.splitlines()
    at = max((i for i, l in enumerate(lines[:end]) if l.lstrip().startswith("#include")), default=None)
    if at is None:                                    # after the leading comment, else at the top
        at = -1
        if lines and lines[0].lstrip().startswith("/*"):
            at = next((i for i, l in enumerate(lines) if "*/" in l), -1)
    lines.insert(at + 1, line)
    write(path, "\n".join(lines) + "\n")
    return True


def declared_in(text: str, name: str) -> bool:
    """A declaration or definition of `name` (a function or an extern) in a C text: the declaration blocks'
    own check (a text being written; the blocks are a lexical edit)."""
    code = TOKEN.sub(" ", text)
    return bool(re.search(rf"\b{re.escape(name)}\s*\(", code) or re.search(rf"\bextern\b[^;]*\b{re.escape(name)}\b", code))


def add_declaration(path: Path, decl: str, name: str, end: int | None = None) -> bool:
    """Append a declaration line to the dcp draft block of a unit's file (created at the end of its head region,
    the first `end` lines: head_end; at the end of the file without); False when the head declares the name
    already."""
    text = path.read_text() if path.exists() else ""
    lines = text.splitlines()
    if declared_in("\n".join(lines[:end]), name):
        return False
    if block_line(lines) is None:
        at = len(lines) if end is None else min(end, len(lines))
        while at > 0 and not lines[at - 1].strip():
            at -= 1
        lines[at:at] = ([""] if at else []) + [DCP_BLOCK, ""]
    i = block_line(lines) + 1
    while i < len(lines) and lines[i].strip() and not lines[i].startswith("/*"):
        i += 1
    lines.insert(i, decl)
    write(path, "\n".join(lines) + "\n")
    return True


def drop_declarations(path: Path, name: str) -> bool:
    """Remove the lines of the dcp draft block that declare `name` (the function is drafted now: its prototype
    lives in its unit's header)."""
    if not path.exists():
        return False
    lines = path.read_text().splitlines()
    if block_line(lines) is None:
        return False
    i = block_line(lines) + 1
    out = lines[:i]
    changed = False
    pat = re.compile(rf"\b{re.escape(name)}\s*\(|\b{re.escape(name)}\s*;")
    while i < len(lines) and lines[i].strip() and not lines[i].startswith("/*"):
        if pat.search(lines[i]):
            changed = True
        else:
            out.append(lines[i])
        i += 1
    out += lines[i:]
    if changed:
        write(path, "\n".join(out) + "\n")
    return changed


def add_to_header(path: Path, unit: str, line: str, name: str) -> bool:
    """Insert a prototype / extern line before the header's closing #endif (the guard is created when the header
    is new); False when the header declares the name already."""
    text = path.read_text() if path.exists() else header_text(unit, "")
    if declared_in(text, name):
        return False
    lines = text.rstrip("\n").splitlines()
    at = max((i for i, l in enumerate(lines) if l.strip().startswith("#endif")), default=len(lines))
    lines.insert(at, line)
    write(path, "\n".join(lines) + "\n")
    return True


def ensure_after_guard(path: Path, unit: str, line: str) -> bool:
    """Put a line (an #include) right after the header's `#define <GUARD>`; False when the header has it."""
    text = path.read_text()
    if line.strip() in (l.strip() for l in text.splitlines()):
        return False
    lines = text.splitlines()
    at = next((i for i, l in enumerate(lines) if l.strip() == f"#define {guard(unit)}"), None)
    lines.insert(at + 1 if at is not None else 0, line)
    write(path, "\n".join(lines) + "\n")
    return True


def header_text(unit: str, what: str) -> str:
    g = guard(unit)
    return (f"/* {unit}.h: the public prototypes and extern declarations of unit {unit}{(': ' + what) if what else ''} */\n"
            f"#ifndef {g}\n#define {g}\n\n#endif\n")
