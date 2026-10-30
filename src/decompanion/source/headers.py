"""`dcp headers conflicts UNIT HEADER..`: what including headers into a unit's head.c would collide with, before
the include is made. A trial amalgamation of the unit (head.c with `#include "<header>"` after its last
include, written to build/lint/<target>/trial/) is parsed by clang the way `dcp lint` parses it (lint.py: the
same flags, system and include directories), and so is the unit as it is; the diagnostics only the trial has
are what the include causes:

  supersedes  a declaration of the unit (head.c or a fragment) the header declares differently (`conflicting
              types`, `redefinition .. with a different type`, a struct defined twice): the local one goes, and
              its users follow the header's type
  duplicate   a declaration of head.c the header repeats with the same type: safe to drop (no diagnostic, by name)
  clash       two headers disagree (both sides in include/): no head edit settles it; one header is wrong
  call        a call of the unit the header's prototype rejects (too few / too many arguments), with the
              original's evidence at the matching call site of the same function: the pushes since the previous
              call (or the function's start) and the `add esp, N` after it (VC6 merges the cleanup of
              consecutive calls, so a missing one says nothing)
  prototyped  a call that compiled without a prototype (implicit or K&R) and now has one: it compiles, but its
              argument conversions (int -> float, the width of a short) may change the code; re-grade it
  header      an error inside a header itself in this unit's include set (a type it needs, a missing include)
  other       any other new error

Then the functions to re-grade: the ones with a `call` / `prototyped` / `supersedes` line in their fragment,
and every function of the unit after any header change (the declaration set alone can move a function's stack
slots). The tool reads only; `--write` inserts the includes and drops the `duplicate` lines of head.c, and only
when the trial without them has no new error at all.
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


def insert_includes(text: str, headers: list[str]) -> str:
    lines = text.split("\n")
    last = max((i for i, l in enumerate(lines) if INCLUDE.match(l)), default=-1)
    add = [f'#include "{h}"   /* dcp headers conflicts: trial */' for h in headers]
    return "\n".join(lines[:last + 1] + add + lines[last + 1:])


def declared_names(rel: str, text: str) -> dict[str, int]:
    """name -> line of every file-scope prototype and extern data declaration of a file."""
    out = {}
    for line, stmt in L.file_scope_prototypes(rel, text):
        m = L.DECL.match(stmt.removeprefix("extern "))
        if m:
            out.setdefault(m.group(2), line)
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

    def raw(self, loc: str) -> str:
        f, _, n = loc.rpartition(":")
        if f not in self.memo:
            p = self.root / f
            self.memo[f] = p.read_text(errors="replace").split("\n") if p.exists() else []
        ls = self.memo[f]
        k = int(n)
        return ls[k - 1] if 0 < k <= len(ls) else ""


def _clang(project, a, text: str, tag: str) -> list[dict]:
    root = Path(project.root)
    out = root / "build" / "lint" / project.target_name / "trial" / f"{a.unit}.{tag}.c"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, newline="\n")
    tc = project.toolchain
    sysdirs = [d for d in tc.include_search_dirs([]) if Path(d).exists()]
    return L.run_clang(L.clang_path(project), out.relative_to(root), root, sysdirs,
                       [root / d for d in B.include_dirs(a.unit)])


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


def trial(project, unit: str, headers: list[str], drop: set[int] = frozenset()):
    """(baseline groups, trial groups, head.c's trial text) of the unit with `headers` included and head.c's
    lines `drop` (1-based) removed."""
    a = next((x for x in B.plan(project) if x.unit == unit), None)
    if a is None:
        raise LookupError(f"no unit {unit} in target {project.target_name}")
    head = next((m.file for m in a.members if m.role == "head"), None)
    if head is None:
        raise LookupError(f"unit {unit} has no head.c")
    old = fsmemo.read_text(Path(project.root) / head)
    lines = old.split("\n")
    kept = "\n".join(l for i, l in enumerate(lines, 1) if i not in drop)
    new = insert_includes(kept, headers)
    base_text, base_segs = A.compose(a.root, a.members, a.file_name)
    new_text, new_segs = A.compose(a.root, a.members, a.file_name, read=_reader(a, new))
    with ThreadPoolExecutor(2) as pool:
        fb = pool.submit(_clang, project, a, base_text, "base")
        fn = pool.submit(_clang, project, a, new_text, "trial")
        base, tri = _map(a, base_segs, fb.result()), _map(a, new_segs, fn.result())
    return a, head, L.grouped(base), L.grouped(tri), new


def analyse(project, unit: str, headers: list[str]):
    from ..ledger.names import Names
    root = Path(project.root)
    a, head, base, tri, new_head = trial(project, unit, headers)
    old_lines = fsmemo.read_text(root / head).split("\n")
    last_inc = max((i for i, l in enumerate(old_lines) if INCLUDE.match(l)), default=-1)
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
    per_callee: dict[str, list] = {}
    for (f, callee), lines in sorted(base_calls.items()):
        if (f, callee) in trial_calls or not is_unit(f):
            continue
        per_callee.setdefault(callee, []).extend((f, ln) for ln in lines)
    for callee, sites in sorted(per_callee.items()):
        fns = sorted({int(m.group(1), 16) for f, _ in sites if (m := FRAG.search(f))})
        it = Item("prototyped", callee, f"{sites[0][0]}:{sites[0][1]}", msg=f"{len(sites)} calls compiled without a "
                  "prototype; the header's now converts their arguments", fns=fns)
        it.sites = [f"{f}:{ln}" for f, ln in sites]
        items.append(it)
    # duplicates: head.c names the headers declare too, without a diagnostic
    hdr_names = {}
    for h in headers:
        for d in B.include_dirs(unit):
            p = root / d / h
            if p.exists():
                rel = p.relative_to(root).as_posix()
                for n, ln in declared_names(rel, fsmemo.read_text(p)).items():
                    hdr_names.setdefault(n, f"{rel}:{ln}")
                break
    for n, ln in sorted(declared_names(head, "\n".join(old_lines)).items(), key=lambda kv: kv[1]):
        if n in hdr_names and n not in conflicting:
            items.append(Item("duplicate", n, f"{head}:{ln}", hdr_names[n], "the header declares it the same way",
                              rd.line(f"{head}:{ln}"), rd.line(hdr_names[n])))
    return a, head, items


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
