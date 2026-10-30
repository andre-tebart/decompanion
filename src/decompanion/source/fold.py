"""`dcp unit fold`: a unit of the fragment layout (src/<unit>/: head.c, f_<addr>.c, u_<name>.c, tail.c, order,
open.md; decompanion before docs/plan.md section 19) into one file, src/<unit>.c, the text the compiler saw:

  - the parts in the old translation unit order: head.c, the fragments in the order file's order (those it
    leaves out after them in address order) or in address order (the file name's), the unlinked fragments by
    name, tail.c; no `#line` between them
  - each fragment's address comment (its first line) moves down to directly above its function's definition
    when the fragment held file-scope definitions before the function (the front end finds the definition)
  - a unit with a declared original file name (decl/data.dcl `file`): every `#line` directive that names a file
    names that one (the old composition gave every part that name), one is added at the top when the head
    has none
  - open.md moves to notes/units/<unit>.md (git mv), the head's comment follows; the parts and the order file go
    (git rm)

A dry run reports what each unit would become; --write writes it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import fsmemo
from ..ledger import srcscan
from . import edit as E

FRAGMENT = re.compile(r"^f_([0-9a-fA-F]+)\.c$")
UNLINKED = re.compile(r"^u_([A-Za-z_]\w*)\.c$")
NAMED_LINE = re.compile(r'^([ \t]*#[ \t]*line[ \t]+\d+[ \t]+)"((?:\\.|[^"\\])*)"', re.M)


@dataclass
class Fold:
    unit: str
    parts: list = field(default_factory=list)      # the part files, in TU order
    moved: list = field(default_factory=list)      # fragments whose address comment moved down to the definition
    file_line: str | None = None                   # the declared file name's directive, when the unit has one
    text: str = ""
    errors: list = field(default_factory=list)


def parts_of(d: Path) -> list[Path]:
    """The part files of a unit directory in the old translation unit order (module docstring)."""
    frags = sorted((p for p in d.glob("f_*.c") if FRAGMENT.match(p.name)), key=lambda p: (int(FRAGMENT.match(p.name).group(1), 16), p.name))
    frags += sorted(p for p in d.glob("u_*.c") if UNLINKED.match(p.name))
    order = d / "order"
    if order.exists():
        listed = [s.strip() for s in order.read_text().split("\n") if s.strip() and not s.strip().startswith("#")]
        pos = {n: k for k, n in enumerate(listed)}
        frags = sorted(frags, key=lambda p: pos.get(p.name, len(pos)))
    return [p for p in [d / "head.c"] if p.exists()] + frags + [p for p in [d / "tail.c"] if p.exists()]


def fold(root: Path, unit: str, file_name: str | None) -> Fold:
    """The folded text of one unit (module docstring); nothing is written."""
    root = Path(root)
    d = root / "src" / unit
    f = Fold(unit, parts_of(d))
    texts = []
    for p in f.parts:
        t = fsmemo.read_text(p)
        texts.append(t if t.endswith("\n") or not t else t + "\n")
    rel = f"src/{unit}.c"
    text = "".join(texts)
    # the fragments' spans in the folded text, and their address comments (the first comment of each)
    spans, at = [], 0
    for p, t in zip(f.parts, texts):
        if FRAGMENT.match(p.name) or UNLINKED.match(p.name):
            spans.append((p, at, at + len(t)))
        at += len(t)
    m = srcscan.model_alone(rel, text, root)
    S = srcscan.Source(rel, text)
    starts = sorted(S.offset(line, col) for line, col, _, _ in m["defs"])
    moves = []                                      # (comment start, comment end incl. its newline, insert at)
    for p, lo, hi in spans:
        c = next((c for c in S.comments if lo <= c[0] < hi), None)
        defs = [s for s in starts if lo <= s < hi]
        if c is None or not defs:
            f.errors.append(f"{p.relative_to(root).as_posix()}: no address comment or no definition found")
            continue
        cs, ce = c[0], c[1]
        if not text[ce:defs[-1]].strip():
            continue
        end = ce + 1 if text[ce:ce + 1] == "\n" else ce
        moves.append((cs, end, text.rfind("\n", 0, defs[-1]) + 1))
        f.moved.append(p.name)
    for cs, end, to in sorted(moves, reverse=True):
        block = text[cs:end] if text[end - 1:end] == "\n" else text[cs:end] + "\n"
        text = text[:cs] + text[end:to] + block + text[to:]
    if file_name is not None:
        esc = file_name.replace("\\", "\\\\")
        f.file_line = f'#line 1 "{esc}"'
        if NAMED_LINE.search(text):
            text = NAMED_LINE.sub(lambda mm: mm.group(1) + '"' + esc + '"', text)
        else:
            text = f.file_line + "\n" + text
    text = text.replace(f"notes in src/{unit}/open.md", f"notes in notes/units/{unit}.md")
    f.text = text
    return f


def write(root: Path, f: Fold):
    """Write src/<unit>.c, move open.md to notes/units/, remove the parts, the order file and the directory."""
    root = Path(root)
    d = root / "src" / f.unit
    out = root / "src" / f"{f.unit}.c"
    if out.exists():
        raise E.EditError(f"{out.relative_to(root).as_posix()} exists")
    for p in f.parts + [d / "order"]:
        E.remove(root, p)
    E.write(out, f.text)
    if (d / "open.md").exists():
        E.move(root, d / "open.md", root / "notes" / "units" / f"{f.unit}.md")
    if d.exists() and not any(d.iterdir()):
        d.rmdir()
