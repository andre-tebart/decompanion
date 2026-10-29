"""The file side of unit commands: `dcp unit new` (the skeleton files), `dcp unit join` and `dcp unit rename`.

A unit's files: src/<unit>/head.c, src/<unit>/f_<addr>.c, src/<unit>/u_<name>.c, src/<unit>/tail.c,
src/<unit>/open.md (the unit's notes: Open work first, then findings) and include/<unit>.h. Its boundaries are
`boundary start|end tu=<unit>` lines of decl/text.dcl (any target prefix). Placeholders of its functions are
spelled `<unit>_<addr>` (source/draft.py), so a join or a rename of the unit renames them too.
"""
from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..ledger import decl as D
from ..ledger import srcscan
from . import edit as E


def head_text(unit: str, lo: int, hi: int | None, by: str | None, why: str) -> str:
    rng = f"{lo:#010x}..{hi:#010x}" if hi is not None else f"{lo:#010x}.."
    return (f"/* {unit}: {why}\n"
            f"   unit {rng}, named by {by or '-'}; boundaries in decl/text.dcl, notes in src/{unit}/open.md */\n"
            f"#include \"{unit}.h\"\n")


def open_md(unit: str, lo: int, hi: int | None, by: str | None, why: str) -> str:
    rng = f"{lo:#010x}..{hi:#010x}" if hi is not None else f"from {lo:#010x}"
    today = datetime.date.today().isoformat()
    return (f"# {unit}\n\n## Open work\n\n- draft every function {rng} in address order (`dcp draft --next`)\n\n"
            f"## Findings\n\n- {today}: unit declared ({rng}, named by {by or '-'}): {why}\n")


def create(root: Path, unit: str, lo: int, hi: int | None, by: str | None, why: str) -> list[str]:
    """Write the skeleton files of a new unit (those that do not exist); the written paths."""
    out = []
    files = {root / "src" / unit / "head.c": head_text(unit, lo, hi, by, why),
             root / "include" / f"{unit}.h": E.header_text(unit, why),
             root / "src" / unit / "open.md": open_md(unit, lo, hi, by, why)}
    for p, text in files.items():
        if not p.exists():
            E.write(p, text)
            out.append(p.relative_to(root).as_posix())
    return out


# ------------------------------------------------------------------------------------------------ decl lines
def rewrite_boundaries(root: Path, targets: list[str], fn) -> list[str]:
    """Rewrite the boundary lines of decl/*.dcl: fn(decl) -> a new Decl, None (drop it) or the same one.
    Returns the changed lines as `old => new` texts."""
    changes = []
    for path in sorted((root / "decl").glob("*.dcl")):
        lines = path.read_text().splitlines()
        out = []
        for raw in lines:
            s = raw.strip()
            if not s or s.startswith("#"):
                out.append(raw)
                continue
            try:
                d = D.parse_line(s)
            except D.DeclError:
                out.append(raw)
                continue
            if d.kind != "boundary":
                out.append(raw)
                continue
            n = fn(d)
            if n is None:
                changes.append(f"- {d.text()}")
                continue
            if n.text() != d.text():
                changes.append(f"{d.text()}  =>  {n.text()}")
            out.append(n.text())
        E.write(path, "\n".join(out) + "\n")
    return changes


def replace_keys(d: D.Decl, **kv) -> D.Decl:
    keys = dict(d.keys)
    for k, v in kv.items():
        if v is None:
            keys.pop(k, None)
        else:
            keys[k] = v
    return D.Decl(d.lo, d.hi, d.kind, d.words, keys, d.reason, d.target, d.file, d.line)


# ------------------------------------------------------------------------------------------------ placeholders
def unit_placeholders(root: Path, unit: str, new: str) -> dict[str, str]:
    """{`<unit>_<addr>` -> `<new>_<addr>`} for every placeholder of the sources spelled with the unit's prefix."""
    pre = E.c_name(unit) + "_"
    out = {}
    for ph in srcscan.scan(root).placeholders:
        if ph.ident.startswith(pre) and re.fullmatch(r"[0-9a-fA-F]{6,8}", ph.ident[len(pre):]):
            out[ph.ident] = E.c_name(new) + "_" + ph.ident[len(pre):]
    return out


# ------------------------------------------------------------------------------------------------ join
@dataclass
class Join:
    moved: list = field(default_factory=list)
    renamed: dict = field(default_factory=dict)
    decl: list = field(default_factory=list)
    removed: list = field(default_factory=list)


def merge_lines(into: str, extra: str, drop: set[str]) -> str:
    """into + the lines of extra that into does not hold (and that are not in drop), in extra's order."""
    have = {l.strip() for l in into.splitlines() if l.strip()}
    add = [l for l in extra.splitlines() if l.strip() and l.strip() not in have and l.strip() not in drop]
    if not add:
        return into
    return into.rstrip("\n") + "\n" + "\n".join(add) + "\n"


def join(root: Path, targets: list[str], a: str, b: str, why: str) -> Join:
    """Move unit b into unit a (module docstring; the caller checked that b directly follows a)."""
    j = Join()
    sa, sb = root / "src" / a, root / "src" / b
    for f in sorted(sb.glob("*.c")):
        if f.name in ("head.c", "tail.c"):
            continue
        dst = sa / f.name
        if dst.exists():
            raise E.EditError(f"{dst.relative_to(root).as_posix()} exists")
        E.move(root, f, dst)
        j.moved.append(f"{f.relative_to(root).as_posix()} -> {dst.relative_to(root).as_posix()}")
    # head.c: a's, plus b's lines a lacks (b's include of its own header becomes a's)
    ha, hb = sa / "head.c", sb / "head.c"
    drop = {f'#include "{b}.h"', f'#include "{a}.h"'}
    if hb.exists():
        text = ha.read_text() if ha.exists() else f'#include "{a}.h"\n'
        E.write(ha, merge_lines(text, hb.read_text(), drop | {l.strip() for l in hb.read_text().splitlines()[:2] if l.lstrip().startswith(("/*", "   unit"))}))
        E.remove(root, hb)
    for tail in (sb / "tail.c",):
        if tail.exists():
            ta = sa / "tail.c"
            E.write(ta, merge_lines(ta.read_text() if ta.exists() else "", tail.read_text(), set()))
            E.remove(root, tail)
    # the headers: b's declarations into a's, before a's #endif
    xa, xb = root / "include" / f"{a}.h", root / "include" / f"{b}.h"
    if xb.exists():
        body = [l for l in xb.read_text().splitlines()
                if l.strip() and not l.startswith(("#ifndef", "#define " + E.guard(b), "#endif", f"/* {b}.h"))]
        text = xa.read_text() if xa.exists() else E.header_text(a, "")
        lines = text.rstrip("\n").splitlines()
        have = {l.strip() for l in lines}
        at = max((i for i, l in enumerate(lines) if l.strip().startswith("#endif")), default=len(lines))
        lines[at:at] = [l for l in body if l.strip() not in have]
        E.write(xa, "\n".join(lines) + "\n")
        E.remove(root, xb)
        j.removed.append(f"include/{b}.h")
    # includes of b's header now name a's
    for p in E.sources(root):
        t = p.read_text(errors="replace")
        if f'#include "{b}.h"' in t:
            seen, out = False, []
            for l in t.splitlines():
                if l.strip() in (f'#include "{b}.h"', f'#include "{a}.h"'):
                    if seen:
                        continue
                    seen = True
                    l = f'#include "{a}.h"'
                out.append(l)
            E.write(p, "\n".join(out) + "\n")
    # notes
    ob, oa = sb / "open.md", sa / "open.md"
    if ob.exists():
        today = datetime.date.today().isoformat()
        text = oa.read_text() if oa.exists() else f"# {a}\n\n## Open work\n\n## Findings\n"
        rest = ob.read_text().split("\n", 1)[1] if "\n" in ob.read_text() else ""
        E.write(oa, text.rstrip("\n") + f"\n\n## joined from {b} ({today}): {why}\n" + rest.replace("\n## ", "\n### "))
        E.remove(root, ob)
    if sb.exists() and not any(sb.iterdir()):
        sb.rmdir()
    j.removed.append(f"src/{b}/")
    # decl: b's start goes, b's end becomes a's end, a's own end (at b's start) goes
    b_start = {}

    def first(d):
        if d.keys.get("tu") == b and d.words[0] == "start":
            b_start[d.target] = d.lo
        return d
    rewrite_boundaries(root, targets, first)

    def fix(d):
        tu = d.keys.get("tu")
        if tu == b and d.words[0] == "start":
            return None
        if tu == a and d.words[0] == "end" and b_start.get(d.target) == d.lo:
            return None
        if tu == b and d.words[0] == "end":
            return replace_keys(d, tu=a)
        return d
    j.decl = rewrite_boundaries(root, targets, fix)
    # placeholders of b's functions are a's now
    j.renamed = unit_placeholders(root, b, a)
    E.rename_words(root, j.renamed)
    return j


# ------------------------------------------------------------------------------------------------ rename
@dataclass
class Rename:
    moved: list = field(default_factory=list)
    renamed: dict = field(default_factory=dict)
    decl: list = field(default_factory=list)
    includes: int = 0


def rename(root: Path, targets: list[str], old: str, new: str, by: str | None) -> Rename:
    """Rename unit old to new: the directory, the header (and its guard), the includes, the boundary lines' tu=
    (and the start's by=), the placeholders `<old>_<addr>`."""
    r = Rename()
    so, sn = root / "src" / old, root / "src" / new
    if sn.exists() or (root / "include" / f"{new}.h").exists():
        raise E.EditError(f"unit {new} exists (src/{new} or include/{new}.h)")
    if so.exists():
        for f in sorted(p for p in so.rglob("*") if p.is_file()):
            dst = sn / f.relative_to(so)
            E.move(root, f, dst)
            r.moved.append(f"{f.relative_to(root).as_posix()} -> {dst.relative_to(root).as_posix()}")
        if so.exists() and not any(so.rglob("*")):
            import shutil
            shutil.rmtree(so, ignore_errors=True)
    ho, hn = root / "include" / f"{old}.h", root / "include" / f"{new}.h"
    if ho.exists():
        E.move(root, ho, hn)
        r.moved.append(f"include/{old}.h -> include/{new}.h")
        t = hn.read_text()
        t = re.sub(rf"\b{re.escape(E.guard(old))}\b", E.guard(new), t)
        t = t.replace(f"/* {old}.h:", f"/* {new}.h:").replace(f"of unit {old}", f"of unit {new}")
        E.write(hn, t)
    for p in E.sources(root):
        t = p.read_text(errors="replace")
        if f'#include "{old}.h"' in t:
            E.write(p, t.replace(f'#include "{old}.h"', f'#include "{new}.h"'))
            r.includes += 1
    head = sn / "head.c"
    if head.exists():
        t = head.read_text()
        if t.startswith(f"/* {old}:"):
            E.write(head, f"/* {new}:" + t[len(f"/* {old}:"):].replace(f"src/{old}/open.md", f"src/{new}/open.md"))
    md = sn / "open.md"
    if md.exists():
        t = md.read_text()
        if t.startswith(f"# {old}\n"):
            E.write(md, f"# {new}\n" + t[len(f"# {old}\n"):])

    def fix(d):
        if d.keys.get("tu") != old:
            return d
        if d.words[0] == "start" and by:
            return replace_keys(d, tu=new, by=by)
        return replace_keys(d, tu=new)
    r.decl = rewrite_boundaries(root, targets, fix)
    r.renamed = unit_placeholders(root, old, new)
    E.rename_words(root, r.renamed)
    return r
