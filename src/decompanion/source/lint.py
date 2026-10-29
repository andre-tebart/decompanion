"""The C compiler of today as the declaration checker of the sources (lifted from the first attempt's
decomp/decl/lint.py). clang parses every translation unit the way VC6 sees it (the amalgamation with its
`#line` directives, MS compatibility, C89 so that `T f();` is a K&R declaration, the toolchain's own headers as
system headers) and reports what VC6 does not. Nothing here changes a byte: clang only reads.

  M6  errors inside one unit: two declarations of one function that disagree, a call with the wrong number of
      arguments, a type VC6 silently accepted
  M5  across units: a generated all-declarations unit (build/lint/<target>/alldecls.c) includes every header of
      include/ and repeats every fragment's and head.c's file-scope prototypes behind `#line`; clang's
      `conflicting types` / `redeclaration` there is one symbol declared differently in two files
  M7  a call through a K&R declaration (-Wdeprecated-non-prototype: every float argument widened, the count
      unchecked) or without any declaration (-Wimplicit-function-declaration); the readability rule Q7 reads
      the same list per fragment
Exemptions, one per line, in the line clang points at or the line of a note it attaches: `@original why` (the
original binary has this mismatch) and `@vc6 why` (VC6 accepts what clang does not). Nothing else silences a
diagnostic.

Cache: per unit in the store's blob table, keyed by the amalgamation's text, the clang flags and the unit's
include hash (the compile's: every file of its include set by content), so a unit is parsed again exactly when
it would be compiled again; the all-declarations unit by its text and the contents of include/. The result of a
run is the store meta `lint` (the input `lint` of M.lint and G.grade).

clang: `[lint] clang = "<path>"` in decompanion.toml, else `clang` on PATH, else the LLVM default install path.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..build import compile as B
from ..ledger import srcscan
from ..ledger.fact import canonical
from ..ledger.store import sha256

FLAGS = ["--target=i386-pc-windows-msvc", "-fms-compatibility", "-fms-extensions", "-fms-compatibility-version=12",
         "-std=gnu89", "-fsyntax-only", "-ferror-limit=0", "-fno-caret-diagnostics", "-fno-color-diagnostics",
         "-Wno-everything", "-Wdeprecated-non-prototype", "-Wimplicit-function-declaration"]
DIAG = re.compile(r"^(.+?):(\d+):(\d+): (error|warning|note): (.*?)(?: \[(-W[\w-]+)\])?$")
EXEMPT = re.compile(r"@(original|vc6)\b")
CALLEE = re.compile(r"'(\w+)'")
DECL = re.compile(r"^\s*((?:[A-Za-z_]\w*[\s\*]+)+?)\b([A-Za-z_]\w*)\s*\(")
KEYWORDS = {"return", "else", "goto", "case", "sizeof", "if", "while", "for", "switch", "do", "typedef", "default"}
DEFAULT_CLANG = "C:/Program Files/LLVM/bin/clang.exe"
VERSION = "1"


def clang_path(project) -> Path | None:
    cfg = (project.cfg.get("lint") or {}).get("clang")
    for c in ([cfg] if cfg else []) + [shutil.which("clang"), DEFAULT_CLANG]:
        if c and Path(c).exists():
            return Path(c)
    return None


def run_clang(clang: Path, src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path]) -> list[dict]:
    cmd = [str(clang), *FLAGS, *(x for d in sysdirs for x in ("-isystem", str(d))), *(f"-I{d}" for d in incdirs), str(src)]
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True, errors="replace")
    out = []
    for line in (r.stdout + r.stderr).splitlines():
        m = DIAG.match(line)
        if not m:
            continue
        f = Path(m.group(1))
        try:
            f = (f if f.is_absolute() else root / f).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            f = f.as_posix()
        out.append({"file": f, "line": int(m.group(2)), "kind": m.group(4), "msg": m.group(5), "flag": m.group(6) or ""})
    return out


def grouped(diags):
    groups = []
    for d in diags:
        if d["kind"] == "note" and groups:
            groups[-1].append(d)
        else:
            groups.append([d])
    return groups


class Lines:
    def __init__(self, root):
        self.root, self.memo = Path(root), {}

    def exempt(self, file: str, line: int) -> bool:
        if file not in self.memo:
            p = self.root / file
            self.memo[file] = p.read_text(errors="replace").split("\n") if p.exists() and p.is_relative_to(self.root) else []
        ls = self.memo[file]
        return 0 < line <= len(ls) and bool(EXEMPT.search(ls[line - 1]))


def fmt_group(g) -> str:
    d = g[0]
    s = f"{d['file']}:{d['line']}: {d['msg']}" + (f" [{d['flag']}]" if d["flag"] else "")
    for n in g[1:]:
        s += f" / note {n['file']}:{n['line']}: {n['msg']}"
    return s


def file_scope_prototypes(rel: str, text: str) -> list[tuple[int, str]]:
    """(line, statement) of every file-scope function declaration that is no definition, not static and no
    function pointer (what the all-declarations unit repeats)."""
    S = srcscan.Source(rel, text)
    code = srcscan.blank_alternatives(S.code)
    out, depth, start = [], 0, 0
    for i, c in enumerate(code):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                start = i + 1
        elif c == ";" and depth == 0:
            stmt = code[start:i]
            m = DECL.match(stmt)
            if m and "=" not in stmt[:m.end()] and not any(t in KEYWORDS for t in re.findall(r"[A-Za-z_]\w*", m.group(1))):
                flat = " ".join(stmt.split())
                head = flat[:flat.find("(")]
                if not flat.startswith(("static", "typedef", "extern \"")) and "(*" not in flat[:flat.find("(") + 2] and "*)" not in head:
                    off = start + len(stmt) - len(stmt.lstrip())
                    out.append((S.line_of(off), flat + ";"))
            start = i + 1
    return out


def alldecls_text(root: Path) -> str:
    lines = ["#include <windows.h>"]
    inc = Path(root) / "include"
    if inc.exists():
        for h in sorted(inc.glob("*.h")):
            lines.append(f'#include "{h.name}"')
    src = Path(root) / "src"
    if src.exists():
        for p in sorted(src.rglob("*.c")):
            rel = p.relative_to(root).as_posix()
            for line, stmt in file_scope_prototypes(rel, p.read_text(errors="replace")):
                lines.append(f'#line {line} "{rel}"')
                lines.append(stmt)
    return "\n".join(lines) + "\n"


def lint(project, log=None) -> dict:
    """Lint every unit of the current target and the all-declarations unit; store and return the result
    {units: {unit: amalg hash}, errors: [M6 lines], cross: [M5 lines], calls: {fragment file: [callee (kind)]}}."""
    root, st, tc = project.root, project.store, project.toolchain
    clang = clang_path(project)
    if clang is None:
        raise RuntimeError("clang not found ([lint] clang = ... in decompanion.toml, or clang on PATH)")
    sysdirs = [d for d in tc.include_search_dirs([]) if Path(d).exists()]
    amalgs = B.plan(project)
    tus = st.tus()
    jobs, results = [], {}
    for a in amalgs:
        B.A.write(root, a)
        inc =(tus.get(a.unit) or {}).get("include_hash", "")
        key = sha256("lint", VERSION, a.text, canonical(FLAGS), inc, canonical([str(d) for d in sysdirs]))
        hit = st.blob_json(key)
        if hit is None:
            jobs.append((a, key))
        else:
            results[a.unit] = hit
    def run(job):
        a, key = job
        return a, key, run_clang(clang, Path(a.path), root, sysdirs, [Path(root) / d for d in B.include_dirs(a.unit)])
    if jobs:
        with ThreadPoolExecutor(os.cpu_count() or 4) as pool:
            for a, key, diags in pool.map(run, jobs):
                st.put_blob_json(key, "lint", diags)
                results[a.unit] = diags
    text = alldecls_text(root)
    akey = sha256("alldecls", VERSION, text, canonical(FLAGS), canonical([str(d) for d in sysdirs]),
                  *(p.read_text(errors="replace") for p in sorted((Path(root) / "include").glob("*.h"))) if (Path(root) / "include").exists() else "")
    cross = st.blob_json(akey)
    if cross is None:
        out = Path(root) / "build" / "lint" / project.target_name / "alldecls.c"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, newline="\n")
        cross = run_clang(clang, out.relative_to(root), root, sysdirs, [Path(root) / "include"])
        st.put_blob_json(akey, "lint", cross)
    lines = Lines(root)
    errors, calls = [], {}
    for a in amalgs:
        for g in grouped(results.get(a.unit, [])):
            d = g[0]
            if any(lines.exempt(x["file"], x["line"]) for x in g):
                continue
            if d["kind"] == "error":
                errors.append(fmt_group(g))
            elif d["kind"] == "warning":
                m = CALLEE.search(d["msg"])
                callee = m.group(1) if m else "?"
                if d["flag"] == "-Wdeprecated-non-prototype" and d["msg"].startswith("passing arguments"):
                    calls.setdefault(d["file"], []).append(f"{callee}() at line {d['line']}")
                elif d["flag"] == "-Wimplicit-function-declaration":
                    calls.setdefault(d["file"], []).append(f"{callee} (undeclared) at line {d['line']}")
    conflicts = []
    for g in grouped(cross):
        d = g[0]
        if d["kind"] != "error":
            continue
        m = re.match(r"(?:conflicting types for|redeclaration of) '(\w+)'", d["msg"])
        if not m or any(lines.exempt(x["file"], x["line"]) for x in g):
            continue
        conflicts.append(fmt_group(g))
    res = {"units": {a.unit: a.src_hash for a in amalgs}, "errors": sorted(set(errors)), "cross": sorted(set(conflicts)),
           "calls": {k: sorted(set(v)) for k, v in sorted(calls.items())}}
    st.set_meta("lint", canonical(res))
    project.forget_input("lint")
    return dict(res, parsed=len(jobs), cached=len(amalgs) - len(jobs))
