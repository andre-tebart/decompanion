"""`dcp headers conflicts UNIT HEADER..`: what including headers into a unit's head.c would collide with, before
the include is made. A trial amalgamation of the unit (head.c with `#include "<header>"` after its last
include, or before the first file-scope statement that uses a name the headers declare when that comes
first, or before the line --at names; written to build/lint/<target>/trial/) is parsed by clang the way `dcp lint` parses it (lint.py: the
same flags, system and include directories), and so is the unit as it is; the diagnostics only the trial has
are what the include causes:

  supersedes  a declaration of the unit (head.c or a fragment) the header declares differently (`conflicting
              types`, `redefinition .. with a different type`, a struct defined twice): the local one goes, and
              its users follow the header's type
  duplicate   a declaration of head.c the header repeats with the same type: safe to drop (no diagnostic, by name;
              each name of a multi-name `extern int a, b, c;` line)
  clash       two headers disagree (both sides in include/): no head edit settles it; one header is wrong
  call        a call of the unit the header's prototype rejects (too few / too many arguments), with the
              original's evidence at the matching call site of the same function: the pushes since the previous
              call (or the function's start) and the `add esp, N` after it (VC6 merges the cleanup of
              consecutive calls, so a missing one says nothing)
  prototyped  a call that compiled without a prototype (implicit or K&R) and now has one: it compiles, but its
              argument conversions (int -> float, the width of a short) may change the code. Per call site
              (every call of the callee in the unit's bodies): `constants: safe` when each argument is a
              constant whose push the prototype cannot change (an integer or string constant to a parameter that
              is no float / double, a floating constant to a double), else re-grade (an expression, an integer
              constant to a floating parameter, a floating constant to a float)
  header      an error inside a header itself in this unit's include set (a type it needs, a missing include)
  vc6         an error only VC6's front end reports (the toolchain's syntax check, `CL /Zs` with the unit's flags,
              over the same two files): clang accepts what VC6 rejects, a struct parameter passed by value whose
              type is incomplete in the unit (C2079) the known case; at a line no clang item names
  other       any other new error

Then the functions to re-grade (a `call` / `vc6` / `supersedes` / `other` line in their fragment, a `prototyped`
call that is not safe) and two warnings:
  declaration-set  the includes add declarations to the unit, or --write drops head.c duplicates: under VC6 /O2
                   the declaration set of a unit alone moves code generation (gildegold: removing uncalled
                   prototypes flipped byte matches to shape), so every function of the unit is re-graded, byte
                   ones first (listed: byte, then shape)
  q6               a duplicate's comment is the only text describing a function's address (rule Q6 reads it):
                   dropping the line drops the function to draft; move the words to its address comment first
                   (a function's address only: Q6 grades functions; a line that keeps a declarator keeps it)
The tool reads only; `--write` inserts the includes and drops the `duplicate` declarations of head.c (a line
whose names are all duplicates goes, comment and all; a multi-name extern line keeps its other declarators),
and only when the trial without them has no new error at all (clang's or VC6's).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .. import fsmemo
from ..build import amalg as A
from ..build import compile as B
from ..ledger import srcscan
from . import lint as L

INCLUDE = re.compile(r"^[ \t]*#[ \t]*include\b")
QUOTED = re.compile(r"'(\w+)'")
C_WORDS = {"struct", "union", "enum", "int", "char", "short", "long", "void", "unsigned", "signed", "float", "double"}
ARGS = re.compile(r"too (few|many) arguments to function call, expected (?:at least )?(\d+), have (\d+)")
CONFLICT = re.compile(r"^(?:conflicting types for|redefinition of|redeclaration of|typedef redefinition with "
                      r"different types|non-static declaration of|static declaration of)\b")
EXTERN = re.compile(r"^\s*extern\b[^;(]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;")
FRAG = re.compile(r"/f_([0-9a-fA-F]+)\.c$")


@dataclass
class Item:
    kind: str                 # supersedes | duplicate | clash | call | prototyped | other
    name: str | None
    at: str                   # file:line of the unit's side (the header's side for a clash)
    other: str | None = None  # file:line of the header's side
    msg: str = ""
    ours: str = ""            # the declaration text on the unit's side
    theirs: str = ""          # on the header's side
    fn: int | None = None     # the fragment's function address
    evidence: list = field(default_factory=list)
    fns: list = field(default_factory=list)     # several functions (prototyped)
    sites: list = field(default_factory=list)
    exempt: bool = False      # a side carries `@original` / `@vc6`: a known divergence, kept on purpose


def symbol_of(g) -> str | None:
    """The symbol a diagnostic group is about: the first quoted identifier that is no C keyword, else the
    `struct X` a typedef redefinition names."""
    for d in g:
        for m in QUOTED.finditer(d["msg"]):
            if m.group(1) not in C_WORDS:
                return m.group(1)
        m = re.search(r"'struct (\w+)'", d["msg"])
        if m:
            return m.group(1)
    return None


def resolve_header(root: Path, unit: str, h: str) -> str | None:
    """The include spelling of h (`d2`, `d2.h`, `include/d2.h`) when one of the unit's include dirs holds it."""
    name = Path(h).name if h.endswith(".h") else f"{Path(h).name}.h"
    for d in B.include_dirs(unit):
        if (Path(root) / d / name).exists():
            return name
    return None


def after_includes(text: str) -> int:
    """The line index (0-based) after head.c's last include (0 without one)."""
    return max((i for i, l in enumerate(text.split("\n")) if INCLUDE.match(l)), default=-1) + 1


def insert_includes(text: str, headers: list[str], pos: int | None = None) -> str:
    """The text with an `#include "h"` line per header inserted before line index `pos` (0-based; default:
    after the last include)."""
    lines = text.split("\n")
    pos = after_includes(text) if pos is None else max(0, min(pos, len(lines)))
    add = [f'#include "{h}"   /* dcp headers conflicts: trial */' for h in headers]
    return "\n".join(lines[:pos] + add + lines[pos:])


IDENT = re.compile(r"\b[A-Za-z_]\w*\b")


def include_pos(rel: str, text: str, names) -> int:
    """Where the includes go in head.c (a line index, 0-based; the includes are inserted before it): after its
    last include, or earlier, at the start of the file-scope statement holding the first use of a name the
    headers declare (`names`) when that use comes first, so a head that uses a duplicate above its last
    include still compiles once the duplicate is dropped. A use is an occurrence outside a declaration line
    of that name."""
    after = after_includes(text)
    names = set(names)
    if not names:
        return after
    S = srcscan.Source(rel, text)
    code = srcscan.blank_alternatives(S.code)
    decl_lines = declared_names(rel, text, every=True)
    first = None
    for m in IDENT.finditer(code):
        n = m.group(0)
        if n in names and S.line_of(m.start()) not in decl_lines.get(n, ()):
            first = S.line_of(m.start()) - 1
            break
    if first is None or first >= after:
        return after
    raw, code_lines = text.split("\n"), code.split("\n")
    inside = set()                           # line indices (0-based) that start inside a comment
    for cs, ce, _ in S.comments:
        inside.update(range(S.line_of(cs), S.line_of(ce - 1)))
    ok, depth, prev = [], 0, ";"             # ok[i]: line i starts a file-scope statement (not in a comment)
    for i, l in enumerate(code_lines):
        ok.append(depth == 0 and i not in inside and prev in ";}#")
        if raw[i].lstrip().startswith("#"):
            prev = "#"
        elif l.strip():
            prev = l.strip()[-1]
        depth += l.count("{") - l.count("}")
    return next((i for i in range(first, -1, -1) if ok[i]), 0)


EXTERN_STMT = re.compile(r"(?:^|(?<=;))([ \t]*)extern\b([^;(]*);")
DECLARATOR = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$")


def drop_names(rel: str, line: str, names) -> str | None:
    """One head.c line without the declarators of `names` in its `extern T a, b, c;` statements: None when no
    code is left (the line goes, its comment with it), else the line with the other declarators (and its
    comment) kept."""
    names = set(names)
    code = srcscan.Source(rel, line).code
    out, pos = [], 0
    for m in EXTERN_STMT.finditer(code):
        chunks = m.group(2).split(",")
        heads = [DECLARATOR.search(c.split("=")[0].rstrip()) for c in chunks]
        if not all(heads):
            continue
        kept = [i for i, h in enumerate(heads) if h.group(1) not in names]
        if len(kept) == len(chunks):
            continue
        spec = chunks[0][:heads[0].start()].rstrip(" \t*")       # `extern int *a, b`: " int"; "*a" is a's
        starts = [m.start(2)]
        for c in chunks:
            starts.append(starts[-1] + len(c) + 1)
        decls = [line[starts[i] + (len(spec) if i == 0 else 0):starts[i] + len(chunks[i])].strip() for i in kept]
        out.append(line[pos:m.start()])
        if kept:
            out.append(m.group(1) + "extern" + line[m.start(2):m.start(2) + len(spec)] + " " + ", ".join(decls) + ";")
        pos = m.end()
    out.append(line[pos:])
    new = "".join(out).rstrip()
    if not srcscan.Source(rel, new).code.strip():
        return None
    return new if line[:1].isspace() else new.lstrip()


def drop_line(rel: str, line: str, names, line_names) -> str | None:
    """A head.c line with its duplicates `names` dropped (drop_names); a line whose declarations
    (`line_names`) are all duplicates but are no extern data statement (a prototype) goes whole: None."""
    new = drop_names(rel, line, names)
    if new is None or new == line and set(line_names) <= set(names):
        return None
    return new


def declared_names(rel: str, text: str, every: bool = False) -> dict:
    """name -> line of every file-scope prototype and extern data declaration of a file (each name of a
    multi-name `extern int a, b, c;`); every=True: name -> the set of its declaration lines."""
    out = {}
    if every:
        for d in L.file_scope_decls(rel, text):
            if d.kind in ("proto", "extern"):
                out.setdefault(d.name, set()).add(d.line)
        return out
    for line, stmt in L.file_scope_prototypes(rel, text):
        m = L.DECL.match(stmt.removeprefix("extern "))
        if m:
            out.setdefault(m.group(2), line)
    for d in L.file_scope_decls(rel, text):
        if d.kind == "extern":
            out.setdefault(d.name, d.line)
    depth = 0
    code = srcscan.blank_alternatives(srcscan.Source(rel, text).code).split("\n")
    for i, l in enumerate(code, 1):
        if depth == 0:
            m = EXTERN.match(l)
            if m:
                out.setdefault(m.group(1), i)
        depth += l.count("{") - l.count("}")
    return out


class Reader:
    def __init__(self, root):
        self.root, self.memo = Path(root), {}

    def line(self, loc: str) -> str:
        return " ".join(self.raw(loc).split())[:160]

    def memo_text(self, f: str) -> str | None:
        p = self.root / f
        return fsmemo.read_text(p) if p.exists() else None

    def raw(self, loc: str) -> str:
        f, _, n = loc.rpartition(":")
        if f not in self.memo:
            p = self.root / f
            self.memo[f] = p.read_text(errors="replace").split("\n") if p.exists() else []
        ls = self.memo[f]
        k = int(n)
        return ls[k - 1] if 0 < k <= len(ls) else ""


def _write(project, a, text: str, tag: str) -> Path:
    root = Path(project.root)
    out = root / "build" / "lint" / project.target_name / "trial" / f"{a.unit}.{tag}.c"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, newline="\n")
    return out.relative_to(root)


def _clang(project, a, rel: Path) -> list[dict]:
    root = Path(project.root)
    tc = project.toolchain
    sysdirs = [d for d in tc.include_search_dirs([]) if Path(d).exists()]
    return L.run_clang(L.clang_path(project), rel, root, sysdirs, [root / d for d in B.include_dirs(a.unit)])


def _vc6(project, a, rel: Path) -> list[dict] | None:
    """The toolchain's own front end over a trial file (VC6: CL /Zs with the unit's flags), as lint-style
    diagnostics; None when it is not installed or has no syntax-only mode. clang accepts what VC6 rejects:
    a struct passed by value whose type is incomplete in the unit (C2079)."""
    tc = project.toolchain
    if not tc.available():
        return None
    root = Path(project.root)
    flags, _ = B.flags_for(project, a.target, a.unit)
    res = tc.syntax_check(rel, flags, B.include_dirs(a.unit), root)
    if res is None:
        return None
    out = []
    for d in res.diagnostics:
        f = Path(d.file) if d.file else Path("")
        try:
            f = (f if f.is_absolute() else root / f).resolve().relative_to(root.resolve()).as_posix() if d.file else ""
        except ValueError:
            f = f.as_posix()
        out.append({"file": f, "line": d.line, "kind": d.severity, "msg": f"{d.code}: {d.message}", "flag": ""})
    return out


def _reader(a, head_text):
    head = next((m.file for m in a.members if m.role == "head"), None)
    return lambda rel: head_text if rel == head else None


def _map(a, segs, diags):
    """Diagnostics of a unit compiled under its declared __FILE__ name mapped back to the part files."""
    if not a.file_name:
        return diags
    fname = a.file_name.lower().replace("\\", "/")
    out = []
    for d in diags:
        if d["file"].lower().replace("\\", "/") == fname:
            hit = [(f, first + d["line"] - lo) for lo, n, f, first in segs if lo <= d["line"] < lo + n]
            if hit:
                d = dict(d, file=hit[0][0], line=hit[0][1])
        out.append(d)
    return out


def _key(g):
    return tuple((d["file"], d["line"], d["msg"]) for d in g)


def head_names(root: Path, unit: str, headers: list[str]) -> dict[str, str]:
    """name -> header file:line of every prototype and extern the headers (and what they include) declare."""
    out = {}
    for rel in header_closure(root, unit, headers):
        for n, ln in declared_names(rel, fsmemo.read_text(Path(root) / rel)).items():
            out.setdefault(n, f"{rel}:{ln}")
    return out


def trial(project, unit: str, headers: list[str], drop: dict | None = None, at: int | None = None):
    """(amalgamation, head.c, baseline groups, trial groups, head.c's trial text, (VC6 baseline, VC6 trial) or
    None, the include position) of the unit with `headers` included and head.c's duplicates `drop` removed
    ({line (1-based): the names to drop there}: the line goes when they are all its names, else only their
    declarators). The includes go before head.c's line `at` (1-based) when given, else where include_pos puts
    them; the position returned is a line index (0-based) of head.c on disk."""
    a = next((x for x in B.plan(project) if x.unit == unit), None)
    if a is None:
        raise LookupError(f"no unit {unit} in target {project.target_name}")
    head = next((m.file for m in a.members if m.role == "head"), None)
    if head is None:
        raise LookupError(f"unit {unit} has no head.c")
    old = fsmemo.read_text(Path(project.root) / head)
    lines = old.split("\n")
    pos = at - 1 if at else include_pos(head, old, head_names(project.root, unit, headers))
    drop = drop or {}
    per_line = {}
    for n, ln in declared_names(head, old).items():
        per_line.setdefault(ln, set()).add(n)
    kept, kpos = [], pos
    for i, l in enumerate(lines, 1):
        if i in drop:
            new_l = drop_line(head, l, drop[i], per_line.get(i, set()))
            if new_l is None:
                kpos -= i <= pos
                continue
            l = new_l
        kept.append(l)
    new = insert_includes("\n".join(kept), headers, kpos)
    base_text, base_segs = A.compose(a.root, a.members, a.file_name)
    new_text, new_segs = A.compose(a.root, a.members, a.file_name, read=_reader(a, new))
    rb, rn = _write(project, a, base_text, "base"), _write(project, a, new_text, "trial")
    with ThreadPoolExecutor(4) as pool:
        fb, fn = pool.submit(_clang, project, a, rb), pool.submit(_clang, project, a, rn)
        vb, vn = pool.submit(_vc6, project, a, rb), pool.submit(_vc6, project, a, rn)
        base, tri = _map(a, base_segs, fb.result()), _map(a, new_segs, fn.result())
        vbase, vtri = vb.result(), vn.result()
    vc6 = None if vbase is None or vtri is None else (_map(a, base_segs, vbase), _map(a, new_segs, vtri))
    return a, head, L.grouped(base), L.grouped(tri), new, vc6, pos


def vc6_new(vc6) -> list[dict]:
    """The VC6 errors only the trial has (by file and message: the trial's head.c lines are shifted)."""
    if vc6 is None:
        return []
    vbase, vtri = vc6
    seen = {(d["file"], d["msg"]) for d in vbase if d["kind"] == "error"}
    return [d for d in vtri if d["kind"] == "error" and (d["file"], d["msg"]) not in seen]


def analyse(project, unit: str, headers: list[str], at: int | None = None):
    from ..ledger.names import Names
    root = Path(project.root)
    a, head, base, tri, new_head, vc6, pos = trial(project, unit, headers, at=at)
    old_lines = fsmemo.read_text(root / head).split("\n")
    last_inc = pos - 1                               # the trial includes follow head.c's line index pos - 1
    n_added = len(headers)
    seen = {_key(g) for g in base}
    base_calls = {}
    for g in base:
        d = g[0]
        if d["kind"] == "warning" and d["flag"] in ("-Wimplicit-function-declaration", "-Wdeprecated-non-prototype"):
            m = QUOTED.search(d["msg"])
            if m:
                base_calls.setdefault((d["file"], m.group(1)), []).append(d["line"])

    def fix(d):                                      # trial head.c lines -> head.c on disk
        if d["file"] == head:
            line = d["line"]
            if last_inc + 1 < line <= last_inc + 1 + n_added:
                return f"{head}:{line} (the trial include)"
            return f"{head}:{line if line <= last_inc + 1 else line - n_added}"
        return f"{d['file']}:{d['line']}"

    def is_unit(f):
        return f.startswith(f"src/{unit}/")

    items, conflicting = [], set()
    rd = Reader(root)
    names = Names(project, project.store)
    trial_calls = set()
    for g in tri:
        d = g[0]
        if d["kind"] == "warning":
            m = QUOTED.search(d["msg"])
            if m and d["flag"] in ("-Wimplicit-function-declaration", "-Wdeprecated-non-prototype"):
                trial_calls.add((d["file"], m.group(1)))
            continue
        if d["kind"] != "error" or _key(g) in seen:
            continue
        name = symbol_of(g)
        m = ARGS.search(d["msg"])
        if m:
            note = next((x for x in g[1:] if "declared here" in x["msg"]), None)
            callee = QUOTED.search(note["msg"]).group(1) if note and QUOTED.search(note["msg"]) else name
            fm = FRAG.search(d["file"])
            it = Item("call", callee, fix(d), fix(note) if note else None, d["msg"], rd.line(fix(d)),
                      rd.line(fix(note)) if note else "", int(fm.group(1), 16) if fm else None)
            it.evidence = call_evidence(project, names, it.fn, callee)
            items.append(it)
            continue
        if CONFLICT.match(d["msg"]) and len(g) > 1:
            note = g[1]
            sides = [d, note]
            ours = next((x for x in sides if is_unit(x["file"])), None)
            theirs = next((x for x in sides if x is not ours and x["file"].startswith("include/")), None)
            if ours is None:
                it = Item("clash", name, fix(d), fix(note), d["msg"], rd.line(fix(d)), rd.line(fix(note)))
                it.exempt = any(L.EXEMPT.search(rd.raw(fix(x))) for x in g)
                items.append(it)
                continue
            conflicting.add(name)
            fm = FRAG.search(ours["file"])
            items.append(Item("supersedes", name, fix(ours), fix(theirs) if theirs else fix(note), d["msg"],
                              rd.line(fix(ours)), rd.line(fix(theirs or note)), int(fm.group(1), 16) if fm else None))
            continue
        if d["file"].startswith("include/") and not any(is_unit(x["file"]) for x in g):
            items.append(Item("header", name, fix(d), None, d["msg"], rd.line(fix(d))))
            continue
        fm = FRAG.search(d["file"])
        items.append(Item("other", name, fix(d), fix(g[1]) if len(g) > 1 else None, d["msg"], rd.line(fix(d)),
                          fn=int(fm.group(1), 16) if fm else None))
    # what VC6 itself rejects and clang accepted (C2079: a struct by value, incomplete in this unit)
    reported = {i.at for i in items}            # VC6's own C2371 of a `supersedes` line says the same
    for d in vc6_new(vc6):
        at = fix(d) if d["file"] else "(command line)"
        if at in reported:
            continue
        reported.add(at)
        fm = FRAG.search(d["file"])
        q = QUOTED.search(d["msg"])
        items.append(Item("vc6", q.group(1) if q else None, at, None, d["msg"], rd.line(at) if d["file"] else "",
                          fn=int(fm.group(1), 16) if fm else None))
    per_callee: dict[str, list] = {}
    for (f, callee), lines in sorted(base_calls.items()):
        if (f, callee) in trial_calls or not is_unit(f):
            continue
        per_callee.setdefault(callee, []).extend((f, ln) for ln in lines)
    # the headers' declarations (and those of what they include)
    hdr_names, hdr_decls = {}, {}
    for rel in header_closure(root, unit, headers):
        text = fsmemo.read_text(root / rel)
        for n, ln in declared_names(rel, text).items():
            hdr_names.setdefault(n, f"{rel}:{ln}")
        for d in L.file_scope_decls(rel, text):
            hdr_decls.setdefault(d.name, d)
    for callee, sites in sorted(per_callee.items()):
        sites = call_sites(root, a, callee) or sites        # clang warns at the first implicit call only
        classes = [(f, ln, call_class(rd.memo_text(f), ln, callee, hdr_decls.get(callee))) for f, ln in sites]
        risky = [(f, ln) for f, ln, c in classes if not c[0]]
        fns = sorted({int(m.group(1), 16) for f, _ in risky if (m := FRAG.search(f))})
        n_safe = len(sites) - len(risky)
        it = Item("prototyped", callee, f"{sites[0][0]}:{sites[0][1]}", msg=f"{len(sites)} calls compiled without a "
                  f"prototype; the header's now converts their arguments: safe={n_safe} (constant arguments, the "
                  f"pushes cannot change) regrade={len(risky)} (float widening / integer promotion may change them)",
                  fns=fns)
        it.sites = [f"{f}:{ln} ({c[1]})" for f, ln, c in classes]
        items.append(it)
    # duplicates: head.c names the headers declare too, without a diagnostic
    for n, ln in sorted(declared_names(head, "\n".join(old_lines)).items(), key=lambda kv: kv[1]):
        if n in hdr_names and n not in conflicting:
            items.append(Item("duplicate", n, f"{head}:{ln}", hdr_names[n], "the header declares it the same way",
                              rd.line(f"{head}:{ln}"), rd.line(hdr_names[n])))
    info = {"vc6": vc6 is not None, "declset": declaration_set(root, a, head, headers, hdr_names),
            "q6": only_descriptions(project, head, old_lines, [i for i in items if i.kind == "duplicate"])}
    return a, head, items, info


def call_sites(root: Path, a, callee: str) -> list[tuple[str, int]]:
    """(file, line) of every call of `callee` inside a function body of the unit's files."""
    pat = re.compile(r"\b" + re.escape(callee) + r"\s*\(")
    out = []
    for m in a.members:
        S = srcscan.Source(m.file, fsmemo.read_text(Path(root) / m.file))
        code = srcscan.blank_alternatives(S.code)
        depth, pos = 0, 0
        for hit in pat.finditer(code):
            for c in code[pos:hit.start()]:
                depth += (c == "{") - (c == "}")
            pos = hit.start()
            if depth > 0:
                out.append((m.file, S.line_of(hit.start())))
    return out


def header_closure(root: Path, unit: str, headers: list[str]) -> list[str]:
    """The project-relative paths of the headers and every header they include (quoted, in the unit's include
    directories), each once."""
    out, todo = [], list(headers)
    while todo:
        h = todo.pop(0)
        for d in B.include_dirs(unit):
            p = Path(root) / d / Path(h).name
            if p.exists():
                rel = p.relative_to(root).as_posix()
                if rel not in out:
                    out.append(rel)
                    todo += [m.group(1) for m in L.INCLUDE_LINE.finditer(fsmemo.read_text(p))]
                break
    return out


def declaration_set(root: Path, a, head: str, headers: list[str], hdr_names: dict) -> dict:
    """What the includes do to the unit's declaration set: the names the headers add (declared nowhere in the
    unit or its current headers) and the head.c declarations --write drops as duplicates."""
    have = set()
    for m in a.members:
        have |= set(declared_names(m.file, fsmemo.read_text(Path(root) / m.file)))
    current = [m.group(1) for m in L.INCLUDE_LINE.finditer(fsmemo.read_text(Path(root) / head))]
    for rel in header_closure(root, a.unit, current):
        have |= set(declared_names(rel, fsmemo.read_text(Path(root) / rel)))
    return {"added": len(set(hdr_names) - have)}


def only_descriptions(project, head: str, old_lines: list[str], dups: list) -> list[tuple]:
    """(duplicate, address) for each head.c duplicate whose comment is the only text describing a function's
    address in the tree (readability rule Q6 reads it): dropping the line drops the description. Only a line
    --write drops whole counts (every name it declares is a duplicate; a line that keeps a declarator keeps
    its comment), each once, and only a function's address (a fragment's; Q6 grades functions, not data)."""
    from collections import Counter
    if not dups:
        return []
    sc = srcscan.scan(project.root, project.input_hash("src"))
    total = Counter(sc.described)
    functions = {a for f in sc.functions for _, a in f.addrs}
    per_line = {}
    for n, ln in declared_names(head, "\n".join(old_lines)).items():
        per_line.setdefault(ln, set()).add(n)
    dup_names = {it.name for it in dups}
    out, done = [], set()
    for it in dups:
        ln = int(it.at.rsplit(":", 1)[1])
        line = old_lines[ln - 1] if 0 < ln <= len(old_lines) else ""
        if ln in done or drop_line(head, line, dup_names, per_line.get(ln, set())) is not None:
            continue
        done.add(ln)
        tmp = srcscan.Scan()
        srcscan.scan_file(head, old_lines[ln - 1] if 0 < ln <= len(old_lines) else "", tmp)
        mine = Counter(tmp.described)
        for addr, n in mine.items():
            if addr in functions and total[addr] - n <= 0:
                out.append((it, addr))
    return out


INT_CONST = re.compile(r"[-+~]?\s*(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*|'(?:\\.|[^'\\])+'|sizeof\b.*|NULL")
FLOAT_CONST = re.compile(r"[-+]?\s*(?:\d+\.\d*|\.\d+|\d+(?=[eE]))(?:[eE][-+]?\d+)?[fFlL]?")
CAST = re.compile(r"^\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*[\s\w]*\**\s*\)")


def _arg_kind(arg: str) -> str:
    """int | float | string | expr: the class of one call argument."""
    s = arg.strip()
    while True:
        m = CAST.match(s)
        if not m or not s[m.end():].strip():
            break
        s = s[m.end():].strip()
    while s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    if s.startswith('"'):
        return "string"
    if FLOAT_CONST.fullmatch(s):
        return "float"
    if INT_CONST.fullmatch(s):
        return "int"
    return "expr"


def call_args(text: str, line: int, callee: str) -> list[str] | None:
    """The argument texts of the first call of `callee` on line `line` (1-based) of a source text."""
    lines = text.split("\n")
    if not 0 < line <= len(lines):
        return None
    off = sum(len(l) + 1 for l in lines[:line - 1])
    m = re.compile(r"\b" + re.escape(callee) + r"\s*\(").search(text, off, off + len(lines[line - 1]))
    if not m:
        return None
    args, depth, cur, i = [], 1, "", m.end()
    while i < len(text) and depth:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < len(text) and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            cur += text[i:j + 1]
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        if c == "," and depth == 1:
            args.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip() or args:
        args.append(cur)
    return [x.strip() for x in args]


def call_class(text: str | None, line: int, callee: str, decl) -> tuple[bool, str]:
    """(safe, why) of a call that compiled without a prototype and gets the header's: safe when every
    argument is a constant whose push the prototype cannot change (an integer or string constant to a
    parameter that is no float / double; a floating constant only to a double)."""
    args = call_args(text or "", line, callee)
    if args is None:
        return False, "call not found: re-grade"
    params = []
    if decl is not None and decl.func:
        s = decl.spelling
        k = s.find("(", s.find(callee))
        params = [p.strip() for p in s[k + 1:s.rfind(")")].split(",")] if k >= 0 else []
    kinds = [_arg_kind(x) for x in args]
    if "expr" in kinds:
        return False, "expressions: re-grade"
    for j, kd in enumerate(kinds):
        p = params[j] if j < len(params) else ""
        floating = bool(re.search(r"\b(float|double)\b", p)) and "*" not in p
        if kd == "float" and not re.search(r"\bdouble\b", p):
            return False, "a floating constant to a float / non-double parameter: re-grade"
        if kd in ("int", "string") and floating:
            return False, "an integer constant to a floating parameter: re-grade"
    return True, "constants: safe" if args else "no arguments: safe"


def call_evidence(project, names, fn: int | None, callee: str | None) -> list[str]:
    """Per call of `callee` inside the original's function `fn`: its site, the pushes since the previous call
    (or the start) and the `add esp, N` right after it."""
    from ..ledger.fact import Kind
    if fn is None or callee is None:
        return []
    tos = names.by_name.get(callee) or []
    if not tos:
        return [f"{callee}: no address known"]
    to = sorted(tos)[0]
    sym = next((f for f in project.store.facts(Kind.symbol, fn, fn + 1) if f.lo == fn and f.value.get("skind") == "func"
                and not f.run.startswith("M.")), None)
    if sym is None:
        return []
    img, isa = project.image, project.isa
    lines = isa.disasm(img.read(sym.lo, sym.hi - sym.lo), sym.lo, project.toolchain.fill_forms)
    out, pushes = [], 0
    for i, ln in enumerate(lines):
        t = ln.text.split()
        op = t[0] if t else ""
        if op == "call":
            if f"{to:#x}" in ln.text.lower() or f"0x{to:x}" in ln.text.lower():
                nxt = lines[i + 1].text if i + 1 < len(lines) else ""
                m = re.match(r"add esp, (0x[0-9a-f]+|\d+)", nxt)
                clean = f"add esp,{m.group(1)} ({int(m.group(1), 0) // 4} args)" if m else "no add esp after"
                out.append(f"original {ln.addr:#010x}: {pushes} pushes since the previous call, {clean}")
            pushes = 0
        elif op == "push":
            pushes += 1
    return out or [f"original: no call of {callee} in {fn:#010x}"]
