"""The C front end: libclang (the LLVM installation's, loaded and walked by the native core:
native/dcp_core/src/clang.rs) parses a translation unit the way VC6 sees it (ARGS: the i386 MSVC target, MS
compatibility, C89 so that `T f();` is a K&R declaration, every warning off but the two M7 reads; the toolchain's
headers as system headers). In process; nothing here changes a byte. This module chooses the parse (a live unit,
a fresh one, the worker processes); every read of a parsed unit is the core's.

libclang: `[lint] libclang = "<path>"` in decompanion.toml, else the libclang.dll beside `clang` on PATH, else the
LLVM default install path (library). load(path) loads it once per process; version() names it in every cache key
of a result derived from a parse (another clang may report otherwise).

diagnostics(src, root, sysdirs, incdirs, defines=(), presumed=False, keep=None) -> [{file, line, kind, msg, flag,
name}], the lint-style list the clang subprocess gave before, in clang's order (a diagnostic followed by its notes):
  file   relative to root when it is inside it, else as clang names it; with `presumed`, in the parsed file the
         name its `#line` directives give (a generated text: the all-declarations unit's pseudo files)
  line   the physical line there: a `#line` directive of a unit (its original `__FILE__` name, its `__LINE__`
         pins) is the compiler's business; with `presumed`, in the parsed file the line its `#line` directives
         give (read from the text, not from clang, whose precompiled preamble drops a `#line` it holds)
  kind   error / warning / note; `flag` the warning option (`-Wdeprecated-non-prototype`) or ""
  name   the symbol the diagnostic is about: the identifier clang quotes in it (libclang hands a diagnostic's
         arguments over only in its text; a call written through a macro names the callee there, where the
         cursor at the location is the macro's expansion, which may hold several calls), `struct X` as X; else
         the declaration, call or reference clang's cursor at its location spells (a call through a function
         pointer), else the identifier token there; None at an expression (`too few arguments` names its callee
         in the `declared here` note)
The `in file included from` notes are left out, as the subprocess's text output carried them in a form lint
never read.

Live units: with `keep`, the parsed unit stays in the process (the last LIVE of them: the daemon's edit loop
parses one unit again and again) with its text and every file it read (their hashes). The next parse of the same
file with the same arguments while those files are unchanged is the live unit itself for the same text (the
scan's model and the lint's diagnostics of one edit share one parse), else a reparse over its precompiled
preamble (the system headers and the unit's leading includes: a small unit in ~10 ms, a large one still parses
its own code); a changed file it read parses afresh. The text is handed over on every parse, so no file stamp of
the parsed file is trusted.

many(jobs): several parses at once (a header edit relints its includers, a first run every unit) go to worker
processes (libclang in threads of one process does not scale: 93 units of gildegold in 2.4 s on 12 threads, in
about half that in processes). The pool lives as long as the process, so the daemon's is warm; one parse runs
in process (with its live unit).
"""
from __future__ import annotations

import os
import shutil
import threading
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .. import native

ARGS = ["--target=i386-pc-windows-msvc", "-fms-compatibility", "-fms-extensions", "-fms-compatibility-version=12",
        "-std=gnu89", "-ferror-limit=0", "-Wno-everything", "-Wdeprecated-non-prototype",
        "-Wimplicit-function-declaration"]
DEFAULT_LIBCLANG = "C:/Program Files/LLVM/bin/libclang.dll"
LIVE = 4                             # live units kept for a reparse (each holds its whole AST)
VERSION = "4"                        # with lint.VERSION and version() in every cached result derived from a parse


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
    """Load libclang once per process; another library later is an error (the core holds one)."""
    global _loaded
    lib = Path(lib).resolve()
    native.core().clang_load(str(lib))
    _loaded = lib


def version() -> str:
    return native.core().clang_version()


def args(sysdirs: list[Path], incdirs: list[Path], defines=()) -> list[str]:
    return [*ARGS, *(x for d in sysdirs for x in ("-isystem", str(d))), *(f"-I{d}" for d in incdirs),
            *(f"-D{d}" for d in defines)]


_live: OrderedDict = OrderedDict()
_lock = threading.Lock()


def _deps(u) -> list[tuple[str, str]]:
    """(path, sha256) of every file a parse read besides the parsed one."""
    from .. import fsmemo
    return [(d, fsmemo.sha256(d)) for d in sorted(set(u.includes()))]


def _unchanged(deps: list[tuple[str, str]]) -> bool:
    from .. import fsmemo
    try:
        return all(fsmemo.sha256(d) == h for d, h in deps)
    except OSError:
        return False


def parse(src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path], text: str | None = None,
          keep: bool | None = None, defines=()):
    """One translation unit (the core's Unit); src relative to root or absolute, its text read when not given;
    defines: the macros the command line defines (a target's `DCP_TARGET_<name>`). keep: as the module says."""
    src = src if src.is_absolute() else Path(root) / src
    text = src.read_text(errors="replace") if text is None else text
    a = args(sysdirs, incdirs, defines)
    core = native.core()
    if not keep:
        return core.clang_parse(str(src), a, text, False)
    key = (os.path.normcase(os.path.abspath(src)), tuple(a))
    with _lock:
        hit = _live.pop(key, None)
    if hit is not None and _unchanged(hit[1]):
        held, deps, u = hit
        if held != text:
            u.reparse(text)
            deps = _deps(u)
    else:
        u = core.clang_parse(str(src), a, text, True)
        deps = _deps(u)
    with _lock:
        _live[key] = (text, deps, u)
        while len(_live) > LIVE:
            _live.popitem(last=False)
    return u


def diagnostics(src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path], defines=(), presumed: bool = False,
                keep: bool | None = None) -> list[dict]:
    path = src if src.is_absolute() else Path(root) / src
    text = path.read_text(errors="replace")
    return parse(path, root, sysdirs, incdirs, text, keep, defines).diagnostics(str(root), text, presumed)


def model(src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path], text: str | None = None,
          defines=(), keep: bool | None = None) -> dict:
    """What the scan reads of one translation unit, per project file it holds (the parsed file, every header
    below root it includes), at the files' physical positions (a `#line` directive maps nothing):
      defs  [(line, col, name, static)] of every function definition that is no inline helper
      decls [("f", name, static, start, name position, end, body start or None, K&R parameters or None) of every
            function declaration and definition (no inline helper); ("v", name, static, start, name position,
            end, kind, initialised, aggregate: an array, struct or union, None for a type clang does not know)
            of every data declarator]: (line, col) positions; the name position is where
            the name is spelled (a rename macro's name: the declared name differs); a definition's parameters
            [(name, `int` / `double` when its type is promoted, else None)] (what a K&R one's prototype says)
      types [(line, name)] of every typedef, every struct / union / enum with a body and every enum constant
            defined there
      dead  [(first line, last line)] of every range the preprocessor skipped (a dead `#if` branch)
      macros [(line, name, function-like)] of every macro the preprocessor defined there (a live `#define`)
      casts [(line, col, end line, end col, literal)] of every integer literal cast to a pointer type in code,
            the cast and the literal spelled in the file, from the cast's `(` to the literal's end: the cursor
            at the `)` before a literal is the cast, stepping over parentheses and casts to a type without a
            pointer (`(char *)(unsigned)0x5de470`); a typedef'd pointer type counts. Comments, strings and dead
            branches have no cursor there
      vars  [(line, col, end line, end col, name, kind, static)] of every file-scope data declarator: (line, col)
            the start of its declaration (one per statement: several declarators share it), (end line, end col)
            the end of the declarator (its initialiser included); kind extern (declared `extern` without an
            initialiser) or def (a definition, a tentative one too)
    plus `deps`, the absolute paths of every file the parse read besides the parsed one (the system headers
    too), and `missing`: an include clang did not find. Columns count characters of the file's text
    (fsmemo.read_text), from 1. keep: as parse's."""
    path = src if src.is_absolute() else Path(root) / src
    text = path.read_text(errors="replace") if text is None else text
    return parse(path, root, sysdirs, incdirs, text, keep, defines).model(str(root), text)


def refs(src: Path, root: Path, sysdirs: list[Path], incdirs: list[Path], text: str, defines, names: list[str],
         keep: bool | None = None) -> dict[str, list[tuple[int, int]]]:
    """rel -> [(line, col)] of every whole-word occurrence of one of `names` in the project files of a translation
    unit (the file, the headers below root it reads) that refers to a declaration not at file scope: a local
    variable, a parameter, a struct / union field, a label (clang's cursor at the occurrence, the declaration it
    refers to or is). What a rename of a file-scope symbol leaves alone; an occurrence in a comment, a string,
    a dead branch or a macro body refers to nothing and is not listed."""
    path = src if src.is_absolute() else Path(root) / src
    return dict(parse(path, root, sysdirs, incdirs, text, keep, defines).refs(str(root), text, list(names)))


def function_headers(sysdirs: list[Path], headers: list[str]) -> dict[str, str]:
    """name -> the header (lower case) of every C-calling-convention function the system headers declare as a
    C compile sees them (dead `#if` branches, `_DEBUG` and C++ only declarations are none), parsed as one
    translation unit that includes `headers` in their order of preference; a name several headers declare
    goes to the first of that order. The library must be loaded (load)."""
    return dict(native.core().clang_function_headers(args(sysdirs, []), list(headers)))


_pool: ProcessPoolExecutor | None = None
WORK = {"diagnostics": diagnostics, "model": model, "refs": refs}


def _work(job):
    fn, lib, args_ = job
    load(lib)
    return WORK[fn](*args_)


def many(jobs: list[tuple], fn: str = "diagnostics") -> list:
    """WORK[fn](*job) for each job, in order (diagnostics: (src, root, sysdirs, incdirs, defines, presumed, keep); model:
    (src, root, sysdirs, incdirs, text, defines, keep); refs: (src, root, sysdirs, incdirs, text, defines, names,
    keep)), keep last: a single job, and the single one to keep among several (the
    unit an edit relints next to the all-declarations unit), in process, where it stays live; the others in the
    worker processes meanwhile, without their keep."""
    global _pool
    if not jobs:
        return []
    if len(jobs) == 1:
        return [WORK[fn](*jobs[0])]
    kept = [k for k, j in enumerate(jobs) if j[-1] is not None]
    here = kept[0] if len(kept) == 1 else None
    if _pool is None:
        _pool = ProcessPoolExecutor(os.cpu_count() or 4)
    futures = {k: _pool.submit(_work, (fn, _loaded, j[:-1])) for k, j in enumerate(jobs) if k != here}
    mine = WORK[fn](*jobs[here]) if here is not None else None
    return [mine if k == here else futures[k].result() for k in range(len(jobs))]
