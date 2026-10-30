"""The C front end: libclang (the LLVM installation's, through the `clang` bindings) parses a translation unit the
way VC6 sees it (ARGS: the i386 MSVC target, MS compatibility, C89 so that `T f();` is a K&R declaration, every
warning off but the two M7 reads; the toolchain's headers as system headers). In process; nothing here changes a
byte.

libclang: `[lint] libclang = "<path>"` in decompanion.toml, else the libclang.dll beside `clang` on PATH, else the
LLVM default install path (library). load(path) loads it once per process; version() names it in every cache key
of a result derived from a parse (another clang may report otherwise).

diagnostics(src, root, sysdirs, incdirs, keep=None) -> [{file, line, kind, msg, flag, name}], the lint-style list
the clang subprocess gave before, in clang's order (a diagnostic followed by its notes):
  file   relative to root when it is inside it; in the parsed file itself the name its `#line` directives give
         (as written, resolved against root), else the header's own path
  line   the line there: in the parsed file through its `#line` directives (line_map: read from the text, not
         from clang, whose precompiled preamble drops a `#line` it holds), else the header's own line
  kind   error / warning / note; `flag` the warning option (`-Wdeprecated-non-prototype`) or ""
  name   the symbol the diagnostic is about: the identifier clang quotes in it (libclang hands a diagnostic's
         arguments over only in its text; a call written through a macro names the callee there, where the
         cursor at the location is the macro's expansion, which may hold several calls), `struct X` as X; else
         the declaration, call or reference clang's cursor at its location spells (a call through a function
         pointer), else the identifier token there; None at an expression (`too few arguments` names its callee
         in the `declared here` note)
The `in file included from` notes are left out, as the subprocess's text output carried them in a form lint
never read.

Live units: with `keep` (the unit's include hash), the parsed unit stays in the process (the last LIVE of them,
the daemon's edit loop lints one unit again and again) and the next parse of the same file with the same
arguments and the same `keep` is a reparse over its precompiled preamble (the system headers and the unit's
leading includes: a small unit in ~10 ms, a large one still parses its own code). The file's text is handed over
on every parse, so a reparse never trusts a file stamp; a changed `keep` (a header changed) parses afresh.

many(jobs): several parses at once (a header edit relints its includers, a first run every unit) go to worker
processes (libclang in threads of one process does not scale: 93 units of gildegold in 2.4 s on 12 threads, in
about half that in processes). The pool lives as long as the process, so the daemon's is warm; one parse runs
in process (with its live unit).
"""
from __future__ import annotations

import bisect
import os
import re
import shutil
import threading
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import clang.cindex as ci

ARGS = ["--target=i386-pc-windows-msvc", "-fms-compatibility", "-fms-extensions", "-fms-compatibility-version=12",
        "-std=gnu89", "-ferror-limit=0", "-Wno-everything", "-Wdeprecated-non-prototype",
        "-Wimplicit-function-declaration"]
KEEP_GOING = 0x200                   # CXTranslationUnit_KeepGoing
OPTIONS = ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD | KEEP_GOING
KIND = {ci.Diagnostic.Note: "note", ci.Diagnostic.Warning: "warning", ci.Diagnostic.Error: "error",
        ci.Diagnostic.Fatal: "error"}
IDENT = re.compile(r"[A-Za-z_]\w*")
LINE = re.compile(r'^[ \t]*#[ \t]*line[ \t]+(\d+)(?:[ \t]+"((?:\\.|[^"\\])*)")?', re.M)
QUOTED = re.compile(r"'(?:(?:struct|union|enum) )?([A-Za-z_]\w*)'")
C_WORDS = {"struct", "union", "enum", "int", "char", "short", "long", "void", "unsigned", "signed", "float", "double"}
DEFAULT_LIBCLANG = "C:/Program Files/LLVM/bin/libclang.dll"
LIVE = 4                             # live units kept for a reparse (each holds its whole AST)
VERSION = "3"                        # with lint.VERSION and version() in every cached result derived from a parse


def library(cfg: dict | None) -> Path | None:
    """The libclang to load for a project configuration (None: the defaults only); None when there is none."""
    want = ((cfg or {}).get("lint") or {}).get("libclang")
    clang = shutil.which("clang")
    for c in [want] if want else [Path(clang).with_name("libclang.dll") if clang else None, DEFAULT_LIBCLANG]:
        if c and Path(c).exists():
            return Path(c)
    return None


_loaded: Path | None = None


def load(lib: Path) -> None:
    """Load libclang once per process; another library later is an error (the bindings hold one)."""
    global _loaded
    lib = Path(lib).resolve()
    if _loaded is None:
        ci.Config.set_library_file(str(lib))
        _loaded = lib
    elif _loaded != lib:
        raise RuntimeError(f"libclang {lib} asked for, {_loaded} already loaded in this process")


def version() -> str:
    f = ci.conf.lib.clang_getClangVersion          # not among the functions the bindings register
    f.argtypes, f.restype = [], ci._CXString
    return ci._CXString.from_result(f())


def args(sysdirs: list[Path], incdirs: list[Path]) -> list[str]:
    return [*ARGS, *(x for d in sysdirs for x in ("-isystem", str(d))), *(f"-I{d}" for d in incdirs)]


def line_map(text: str, name: str) -> tuple[list[int], list[tuple[str, int]]]:
    """The `#line` directives of a text: (their physical lines, (file, number) after each), the file itself first."""
    lines, at = [0], [(name, 1)]
    ln, pos = 1, 0
    for m in LINE.finditer(text):
        f = m.group(2).replace("\\\\", "\\") if m.group(2) is not None else at[-1][0]
        ln += text.count("\n", pos, m.start())
        pos = m.start()
        lines.append(ln)
        at.append((f, int(m.group(1))))
    return lines, at


def locate(lmap, line: int) -> tuple[str, int]:
    """A physical line of the parsed file -> (the file, the line) its `#line` directives give it."""
    lines, at = lmap
    k = bisect.bisect_left(lines, line) - 1         # the last directive above the line
    f, n = at[k]
    return f, n + line - lines[k] - 1


_live: OrderedDict = OrderedDict()
_lock = threading.Lock()


def parse(src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path], text: str | None = None,
          keep: str | None = None) -> ci.TranslationUnit:
    """One translation unit; src relative to root or absolute, its text read when not given."""
    src = src if src.is_absolute() else Path(root) / src
    text = src.read_text(errors="replace") if text is None else text
    a = args(sysdirs, incdirs)
    unsaved = [(str(src), text)]
    if keep is None:
        return ci.Index.create().parse(str(src), args=a, unsaved_files=unsaved, options=OPTIONS)
    key = (str(src), tuple(a))
    with _lock:
        hit = _live.pop(key, None)
    if hit is not None and hit[1] == keep:
        idx, _, tu = hit
        tu.reparse(unsaved_files=unsaved)
    else:
        idx = ci.Index.create()
        tu = idx.parse(str(src), args=a, unsaved_files=unsaved,
                       options=OPTIONS | ci.TranslationUnit.PARSE_PRECOMPILED_PREAMBLE)
    with _lock:
        _live[key] = (idx, keep, tu)
        while len(_live) > LIVE:
            _live.popitem(last=False)
    return tu


def rel(root: Path, f: str) -> str:
    p = Path(f)
    try:
        return (p if p.is_absolute() else root / p).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def name_of(tu: ci.TranslationUnit, d: ci.Diagnostic) -> str | None:
    for m in QUOTED.finditer(d.spelling):
        if m.group(1) not in C_WORDS:
            return m.group(1)
    return name_at(tu, d.location)


def name_at(tu: ci.TranslationUnit, loc: ci.SourceLocation) -> str | None:
    """The symbol at a location: the cursor's spelling when it is an identifier (a declaration, a call, a
    reference), else the identifier token there (a tag clang's recovery left unnamed)."""
    if loc.file is None:
        return None
    c = ci.Cursor.from_location(tu, loc)
    if c is not None and IDENT.fullmatch(c.spelling or ""):
        return c.spelling
    for t in tu.get_tokens(extent=ci.SourceRange.from_locations(loc, loc)):
        if t.kind == ci.TokenKind.IDENTIFIER and t.location == loc:
            return t.spelling
    return None


def diagnostics(src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path], keep: str | None = None) -> list[dict]:
    root = Path(root)
    path = src if src.is_absolute() else root / src
    text = path.read_text(errors="replace")
    tu = parse(path, root, sysdirs, incdirs, text, keep)
    lmap = line_map(text, str(path))
    main = path.resolve()
    files: dict[str, tuple[bool, str]] = {}          # clang's file name -> (the parsed file?, relative path)
    out = []

    def one(d, kind):
        loc = d.location
        if loc.file is None:
            return False                 # no location (the command line): the subprocess's text had no file:line
        f, line = loc.file.name, loc.line
        if f not in files:
            files[f] = (Path(f).resolve() == main, rel(root, f))
        is_main, fr = files[f]
        if is_main:
            mf, line = locate(lmap, line)
            fr = rel(root, mf)
        out.append({"file": fr, "line": line, "kind": kind, "msg": d.spelling, "flag": d.option or "",
                    "name": name_of(tu, d)})
        return True

    for d in tu.diagnostics:
        if d.severity < ci.Diagnostic.Warning or not one(d, KIND[d.severity]):
            continue
        for n in d.children:
            if not n.spelling.startswith("in file included from"):
                one(n, "note")
    return out


_pool: ProcessPoolExecutor | None = None


def _work(job) -> list[dict]:
    lib, src, root, sysdirs, incdirs = job
    load(lib)
    return diagnostics(src, root, sysdirs, incdirs)


def many(jobs: list[tuple[Path, Path, list[Path], list[Path], str | None]]) -> list[list[dict]]:
    """diagnostics(src, root, sysdirs, incdirs, keep) for each job, in order: a single job, and the single one to
    keep among several (the unit an edit relints next to the all-declarations unit), in process, where it stays
    live; the others in the worker processes meanwhile."""
    global _pool
    if len(jobs) == 1:
        return [diagnostics(*jobs[0])]
    kept = [k for k, j in enumerate(jobs) if j[4] is not None]
    here = kept[0] if len(kept) == 1 else None
    if _pool is None:
        _pool = ProcessPoolExecutor(os.cpu_count() or 4)
    futures = {k: _pool.submit(_work, (_loaded, *j[:4])) for k, j in enumerate(jobs) if k != here}
    mine = diagnostics(*jobs[here]) if here is not None else None
    return [mine if k == here else futures[k].result() for k in range(len(jobs))]
