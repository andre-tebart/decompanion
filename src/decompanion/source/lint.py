"""The C compiler of today as the declaration checker of the sources (lifted from the first attempt's
decomp/decl/lint.py). clang parses every translation unit the way VC6 sees it (src/<unit>.c with the target's
DCP_TARGET_<name> defined, MS compatibility, C89 so that `T f();` is a K&R declaration, the toolchain's own headers as
system headers) and reports what VC6 does not. Nothing here changes a byte: clang only reads.

  M6  errors inside one unit: two declarations of one function that disagree, a call with the wrong number of
      arguments, a type VC6 silently accepted
  M5  across units: a generated all-declarations unit (build/lint/<target>/alldecls.c, `alldecls`) includes the
      system headers the sources include, every header of include/ (a header after the headers that define
      the names it uses, and after its includer), repeats every source's file-scope prototypes and extern data
      declarations behind `#line` (with the macros of its unit that they use: `GAPDATA`), then every
      non-static definition of the sources (a function's head as a prototype, a K&R definition with an empty
      body, a data definition as an extern declaration). One M5 line per symbol:
        - with a definition: every other spelling of the symbol is renamed (`__dcp_<n>`, pseudo file
          @dcp-copy) and compared with the renamed definition by `__builtin_types_compatible_p` on their
          addresses (@dcp-check): each declaration's file:line agrees or disagrees with the definition (or is
          unknown: it uses a type of its unit), whatever order clang would see them in
        - without one (or with a definition that uses a type of its unit): clang's own pairs, each
          redeclaration against the first declaration seen
        - a struct, union, enum or typedef two headers define differently (`redefinition`)
        - a header that does not compile there (its declarations are not compared: their conflicts hidden)
      Errors that are no conflict are clang's business elsewhere (a unit-local type, a macro the unit does not
      have), and a pair whose two sides read the same, or one side of which has an error of its own, is
      clang's error recovery, not a disagreement. An `@original` / `@vc6` exemption applies to a declaration
      in src/ only: a header is included into many units and repeats the definition's spelling; a unit's own
      view goes into that unit (a cast macro in its head region). A header marked `@private UNIT[,..]` in its first
      20 lines (the original only included it into those units) is left out of the unit, and a file outside
      those units that includes it is an M5 error
  M7  a call through a K&R declaration (-Wdeprecated-non-prototype: every float argument widened, the count
      unchecked) or without any declaration (-Wimplicit-function-declaration); the readability rule Q7 reads
      the calls inside each function's span
Exemptions, one per line, in the line clang points at or the line of a note it attaches: `@original why` (the
original binary has this mismatch) and `@vc6 why` (VC6 accepts what clang does not). Nothing else silences a
diagnostic.

Cache: per unit in the store's blob table, keyed by the unit's text, the clang arguments and the unit's
include hash (the compile's: every file of its include set by content), so a unit is parsed again exactly when
it would be compiled again; the all-declarations unit by its text and the contents of include/. The result of a
run is the store meta `lint` (the input `lint` of M.lint and G.grade).

clang: the LLVM installation's libclang in process (source/cparse.py: `[lint] libclang = "<path>"` in
decompanion.toml, else beside `clang` on PATH, else the LLVM default install path); the units a lint parses at
once go to cparse's worker processes; a unit alone stays live (cparse.parse: the scan's parse of an edit serves its lint).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .. import fsmemo, native, timing
from ..build import compile as B
from ..ledger import srcscan
from ..ledger.fact import canonical
from ..ledger.store import sha256

EXEMPT = re.compile(r"@(original|vc6)\b")
VERSION = "7"


NOT_FOUND = ("libclang not found ([lint] libclang = ... in decompanion.toml, or an LLVM installation: clang on PATH "
             "or C:/Program Files/LLVM)")


def available(project) -> bool:
    from . import cparse
    return cparse.library(project.cfg) is not None


def setup(project) -> None:
    """Load the project's libclang (cparse.library) into this process."""
    from . import cparse
    lib = cparse.library(project.cfg)
    if lib is None:
        raise RuntimeError(NOT_FOUND)
    cparse.load(lib)


def sysdirs_of(project) -> list[Path]:
    return [Path(d) for d in project.toolchain.include_search_dirs([]) if Path(d).exists()]


def call_of(d) -> tuple[str, str] | None:
    """An M7 call: (callee, `proto` through a K&R declaration / `undeclared`); None for any other diagnostic
    (-Wdeprecated-non-prototype also stands at a K&R declaration itself)."""
    if d["kind"] != "warning":
        return None
    if d["flag"] == "-Wdeprecated-non-prototype" and d["msg"].startswith("passing arguments"):
        return d.get("name") or "?", "proto"
    if d["flag"] == "-Wimplicit-function-declaration":
        return d.get("name") or "?", "undeclared"
    return None


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


@dataclass(frozen=True)
class Decl:
    """One file-scope declaration or definition of a function or a data object, as the all-declarations unit
    repeats it (whitespace collapsed, comments and strings blanked)."""
    file: str
    line: int
    last: int                 # the statement's last line (an exemption may stand on any of its lines)
    name: str
    kind: str                 # proto | extern (declarations); fdef | knr | ddef (definitions; ddef as extern)
    stmt: str                 # the statement as emitted: `...;`, a K&R definition `... {}`
    at: int                   # offset of the name in stmt (a renamed copy replaces it)
    init: bool = False        # ddef: it has an initialiser (the definition of a tentatively defined name)
    proto: str = ""           # knr: the prototype its parameter declarations spell (what its copy compares)

    @property
    def func(self) -> bool:
        return self.kind in ("proto", "fdef", "knr")

    @property
    def definition(self) -> bool:
        return self.kind in ("fdef", "knr", "ddef")

    @property
    def spelling(self) -> str:
        s = self.stmt[:-3] if self.stmt.endswith(" {}") else self.stmt.rstrip(";")
        return s.removeprefix("extern ").strip()

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}"

    def renamed(self, new: str) -> str:
        if self.proto:
            k = _name_at(self.proto, self.name)
            return self.proto[:k] + new + self.proto[k + len(self.name):]
        return self.stmt[:self.at] + new + self.stmt[self.at + len(self.name):]


def _name_at(stmt: str, name: str) -> int:
    """The offset of the declared name in a collapsed declaration: the occurrence followed by a declarator
    end (`(`, `[`, `)`, `;`, `,`, `=`), else the first one."""
    m = re.search(r"(?<![\w])" + re.escape(name) + r"(?=\s*[(\[);,=]|\s*$)", stmt)
    if m is None:
        m = re.search(r"\b" + re.escape(name) + r"\b", stmt)
    return m.start() if m else -1


def file_scope_decls(rel: str, text: str, m: dict | None = None) -> list[Decl]:
    """Every file-scope declaration and definition of a function or data object that is not static, in file
    order: prototypes (`proto`), extern data (`extern`), function definitions (`fdef` as a prototype of their
    head, `knr` a K&R definition with an empty body) and data definitions (`ddef`, as an extern declaration).
    Typedefs, tags, `__inline` bodies and function pointer types are left out. The declarations are the
    front end's (m: the file's cparse.model entry, `decls`), their text cut from the file by their positions
    (comments blanked, whitespace collapsed); a declaration whose spelled name is not the declared one (a rename
    macro, `#define X X_ag`, declares X_ag) is left out. Without m the text is parsed alone
    (srcscan.model_alone)."""
    m = srcscan.model_alone(rel, text) if m is None else m
    return [Decl(*r) for r in native.core().lint_file_decls(rel, text, m)]


PRIVATE = re.compile(r"@private[ \t]+([A-Za-z_][\w]*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)")
INCLUDE_LINE = re.compile(r'^[ \t]*#[ \t]*include[ \t]+"([^"]+)"', re.M)


def private_headers(root: Path) -> dict[str, set[str]]:
    """header name -> the units it is private to (`@private UNIT[,UNIT..]` in its first 20 lines): a header
    the original only ever included into those units (zlib's deflate.h, infutil.h define one struct tag
    each), left out of the all-declarations unit."""
    out = {}
    inc = Path(root) / "include"
    for h in sorted(inc.glob("*.h")) if inc.exists() else []:
        m = PRIVATE.search("\n".join(fsmemo.read_text(h).split("\n")[:20]))
        if m:
            out[h.name] = {u.strip() for u in m.group(1).split(",")}
    return out


def private_violations(root: Path, private: dict[str, set[str]]) -> list[str]:
    """M5 lines: a file outside a private header's units that includes it (a header including it counts only
    when it is private to a subset of those units)."""
    out = []
    if not private:
        return out
    root = Path(root)
    files = [("src/" + rel, p) for rel, p in fsmemo.walk(root / "src", ("*.c",))] if (root / "src").exists() else []
    files += [(f"include/{h.name}", h) for h in sorted((root / "include").glob("*.h"))] if (root / "include").exists() else []
    for rel, p in files:
        for h, line in quoted_includes(rel, p):
            units = private.get(h)
            if units is None:
                continue
            if rel.startswith("src/"):
                ok = Path(rel).stem in units
            else:
                ok = Path(rel).name == h or private.get(Path(rel).name, {None}) <= units
            if not ok:
                out.append(f"{rel}:{line}: includes {h}, private to {','.join(sorted(units))} (@private in the header)")
    return out


_quoted: dict[tuple, list] = {}         # (file, its text's hash) -> its `#include "..."` (header name, line)


def quoted_includes(rel: str, p: Path) -> list[tuple[str, int]]:
    """The `#include "..."` of a file: (the header's name, the line), kept while the file's text stands."""
    key = (rel, fsmemo.sha256(p))
    hit = _quoted.get(key)
    if hit is None:
        if len(_quoted) > 5000:
            _quoted.clear()
        text = fsmemo.read_text(p)
        hit = _quoted[key] = [(Path(m.group(1)).name, text.count("\n", 0, m.start()) + 1) for m in INCLUDE_LINE.finditer(text)]
    return hit


def native_alldecls(root: Path, sc, target: str | None):
    """The all-declarations unit of a target (module docstring, M5) built by the core from the scan's pieces
    (native/dcp_core/src/lint.rs): every header of include/ that is not private, the sources src/**/*.c."""
    root = Path(root)
    inc, src = root / "include", root / "src"
    private = private_headers(root)
    headers = [f"include/{h.name}" for h in sorted(inc.glob("*.h")) if h.name not in private] if inc.exists() else []
    srcs = ["src/" + rel for rel, _ in fsmemo.walk(src, ("*.c",))] if src.exists() else []
    return native.core().lint_alldecls([x.id for x in sc.native], target, headers, srcs)


def stale(project) -> list[str] | None:
    """The units whose source or include set changed since the last lint (by the compile's hashes), None when
    there was no lint run: the lint result (Q7, M5..M7) is current exactly when this is empty."""
    m = project.store.meta("lint")
    if m is None:
        return None
    m = json.loads(m)
    units, includes = m.get("units", {}), m.get("includes", {})
    tus = project.store.tu_keys()
    changed = {u for u, row in tus.items() if units.get(u) != row["src_hash"] or includes.get(u) != row["include_hash"]}
    return sorted(changed | (set(units) - set(tus)))


def lint(project, log=None) -> dict:
    """Lint every unit of the current target and the all-declarations unit; store and return the result
    {units: {unit: text hash}, errors: [M6 lines], cross: [M5 lines], calls: {file: [[line, callee (kind)]]}}."""
    from . import cparse
    root, st = project.root, project.store
    setup(project)
    sysdirs = sysdirs_of(project)
    clang = (cparse.VERSION, cparse.version(), canonical(cparse.ARGS), canonical([str(d) for d in sysdirs]))
    units_ = B.plan(project)
    defines = [srcscan.target_macro(project.target_name)]
    tus = st.tu_keys()
    jobs, keys, results = [], [], {}
    for a in units_:
        inc = (tus.get(a.unit) or {}).get("include_hash", "")
        key = sha256("lint", VERSION, *clang, a.src_hash, inc, *defines)
        hit = st.blob_json(key)
        if hit is None:
            # kept live: the scan's parse of the same text, the next lint of the unit alone (an edit of it) a reparse
            jobs.append((Path(a.path), root, sysdirs, [Path(root) / d for d in B.include_dirs(a.unit)], defines, False, True))
            keys.append((a.unit, key))
        else:
            results[a.unit] = hit
    with timing.phase("lint.alldecls"):
        ad = native_alldecls(root, srcscan.scan(root, project.input_hash("src")), project.target_name)
    text = ad.text
    akey = sha256("alldecls", VERSION, *clang, text, *defines,
                  *(fsmemo.sha256(p) for p in sorted((Path(root) / "include").glob("*.h"))) if (Path(root) / "include").exists() else "")
    cross = st.blob(akey)                       # its diagnostics as JSON text (the core reads them)
    if cross is None:
        out = Path(root) / "build" / "lint" / project.target_name / "alldecls.c"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, newline="\n")
        jobs.append((out.relative_to(root), root, sysdirs, [Path(root) / "include"], defines, True, None))
        keys.append((None, akey))
    with timing.phase("lint.parse"):
        parsed = cparse.many(jobs) if jobs else []
    timing.add("lint.jobs", len(jobs))
    for (unit, key), diags in zip(keys, parsed):
        st.put_blob_json(key, "lint", diags)
        if unit is None:
            cross = canonical(diags).encode()
        else:
            results[unit] = diags
    jobs = [k for k in keys if k[0] is not None]
    lines = Lines(root)
    errors, calls = [], {}
    for a in units_:
        for g in grouped(results.get(a.unit, [])):
            d = g[0]
            if any(lines.exempt(x["file"], x["line"]) for x in g):
                continue
            if d["kind"] == "error":
                errors.append(fmt_group(g))
            elif c := call_of(d):
                callee, how = c
                calls.setdefault(d["file"], []).append((d["line"], f"{callee}() at line {d['line']}" if how == "proto" else
                                                                     f"{callee} (undeclared) at line {d['line']}"))
    with timing.phase("lint.cross"):
        conflicts = native.core().lint_cross(ad, cross.decode(), str(root))
    conflicts += private_violations(root, private_headers(root))
    res = {"units": {a.unit: a.src_hash for a in units_},
           "includes": {a.unit: (tus.get(a.unit) or {}).get("include_hash", "") for a in units_}, "errors": sorted(set(errors)), "cross": sorted(set(conflicts)),
           "calls": {k: [list(c) for c in sorted(set(v))] for k, v in sorted(calls.items())}}
    st.set_meta("lint", canonical(res))
    project.forget_input("lint")
    return dict(res, parsed=len(jobs), cached=len(units_) - len(jobs))
