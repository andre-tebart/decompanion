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

from .. import fsmemo, timing
from ..build import compile as B
from ..ledger import srcscan
from ..ledger.fact import canonical
from ..ledger.store import sha256

EXEMPT = re.compile(r"@(original|vc6)\b")
DECL = re.compile(r"^\s*((?:[A-Za-z_]\w*[\s\*]+)+?)\b([A-Za-z_]\w*)\s*\(")
# M5: a symbol declared differently in two files of the all-declarations unit; a struct / union / enum or
# typedef defined twice counts too (two headers that define one tag cannot be included together)
CROSS = re.compile(r"(?:conflicting types for|redeclaration of|redefinition of|typedef redefinition with different "
                   r"types) ('(\w+)'|\()")
KEYWORDS = {"return", "else", "goto", "case", "sizeof", "if", "while", "for", "switch", "do", "typedef", "default"}
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


def _flat(s: str) -> str:
    return " ".join(s.split())


def _name_at(stmt: str, name: str) -> int:
    """The offset of the declared name in a collapsed declaration: the occurrence followed by a declarator
    end (`(`, `[`, `)`, `;`, `,`, `=`), else the first one."""
    m = re.search(r"(?<![\w])" + re.escape(name) + r"(?=\s*[(\[);,=]|\s*$)", stmt)
    if m is None:
        m = re.search(r"\b" + re.escape(name) + r"\b", stmt)
    return m.start() if m else -1


DECLARATOR_LEAD = re.compile(r"(?:\s|\*|\(|\b(?:const|volatile|__cdecl|__stdcall|__fastcall|far|near)\b)*$")


def _declarator_name(chunk: str) -> str | None:
    fp = srcscan.FUNCPTR.search(chunk)
    if fp:
        return fp.group(1)
    ws = re.findall(r"[A-Za-z_]\w*", re.sub(r"\[[^\]]*\]", "", chunk))
    return ws[-1] if ws else None


def _data_decls(head: str, names: list[str] | None = None) -> list[tuple[str, str]] | None:
    """(name, `extern` declaration) per declarator of a data statement (`head` without its `;`): the
    initialisers dropped, the base type repeated for each declarator; the names from the declarators when
    `names` does not give one per declarator."""
    chunks, d, cur = [], 0, []
    for c in head:
        d += c in "([{"
        d -= c in ")]}"
        if c == "," and d == 0:
            chunks.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    chunks.append("".join(cur))
    cut = []
    for ch in chunks:
        d = 0
        for j, c in enumerate(ch):
            d += c in "([{"
            d -= c in ")]}"
            if c == "=" and d == 0:
                ch = ch[:j]
                break
        cut.append(ch)
    if names is None or len(names) != len(cut):
        names = [_declarator_name(ch) for ch in cut]
        if not all(names):
            return None
    k = _name_at(cut[0], names[0])
    if k < 0:
        return None
    pos = DECLARATOR_LEAD.search(cut[0][:k]).start()
    base = re.sub(r"^\s*extern\b", "", cut[0][:pos])
    cut[0] = cut[0][pos:]
    return [(n, _flat("extern " + base + " " + ch) + ";") for n, ch in zip(names, cut)]


SMALL_INT = {"char", "short"}
INT_WORDS = {"const", "volatile", "register", "signed", "unsigned", "char", "short", "int"}


def _promoted(decl: str, name: str) -> str:
    """A K&R parameter declaration `T name` with T default-promoted (char / short -> int, float -> double): what
    the caller pushes and what a prototype of the function has to say (C89 6.5.4.3 / C99 6.7.5.3p15)."""
    k = _name_at(decl, name)
    base = decl[:k].strip() if k >= 0 else decl
    if "*" in decl or "[" in decl or "(" in decl:
        return decl
    words = base.split()
    if words and set(words) <= INT_WORDS and set(words) & SMALL_INT:
        return f"int {name}"
    if [w for w in words if w not in ("const", "volatile", "register")] == ["float"]:
        return f"double {name}"
    return decl


def _knr_prototype(head: str, between: str, name: str) -> str:
    """The prototype a K&R definition's parameter declarations spell, default-promoted (`int` for an undeclared
    one): a K&R definition's own type has no parameters to compare."""
    m = re.search(r"\b" + re.escape(name) + r"\s*\(", head)
    k = m.end() - 1 if m else head.find("(")
    params = [w.strip() for w in head[k + 1:head.rfind(")")].split(",") if w.strip()]
    types = {}
    for decl in between.split(";"):
        if not decl.strip():
            continue
        for n, d in _data_decls(decl) or []:
            types[n] = _promoted(_flat(d.removeprefix("extern ").rstrip(";")), n)
    return _flat(head[:k] + "(" + (", ".join(types.get(n, f"int {n}") for n in params) or "void") + ")") + ";"


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
    S = srcscan.Source(rel, text)
    code = S.code
    off = lambda lc: S.offset(*lc)
    out = []
    stmts: dict[tuple, list] = {}
    for d in m["decls"]:
        stmts.setdefault(tuple(d[3]), []).append(d)

    def stmt_end(n: int) -> tuple[int, list[int]]:
        """(the `;` that ends the statement starting at n, the depth-0 commas before it): read from
        the text, as an extent ending in a macro call (`int f OF((int a));`) reads back as the call's start."""
        j, depth, commas = n, 0, []
        while j < len(code):
            c = code[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0 and c == ",":
                commas.append(j)
            elif depth == 0 and c == ";":
                break
            j += 1
        return j, commas

    def declarators(group, s, e, commas):
        """(base, [declarator text]) of a statement: the base type before the first declarator (its `*` / `(` /
        qualifiers belong to the declarator), the declarators split at the commas, each initialiser cut."""
        n0 = off(group[0][4])
        base_end = s + DECLARATOR_LEAD.search(code[s:n0]).start()
        bounds = [base_end] + [c + 1 for c in commas] + [e + 1]
        texts = []
        for a, b in zip(bounds, bounds[1:]):
            t = code[a:b - 1]
            depth = 0
            for j, c in enumerate(t):
                depth += c in "([{"
                depth -= c in ")]}"
                if c == "=" and depth == 0:
                    t = t[:j]
                    break
            texts.append(t)
        return code[s:base_end], texts

    for start, group in stmts.items():
        s = off(start)

        def kept(d) -> bool:                  # not static, its spelled name the declared one (no rename macro)
            m_ = IDENT.match(code, off(d[4]))
            return not d[2] and m_ is not None and m_.group(0) == d[1]
        if not any(kept(d) for d in group):
            continue
        line = S.line_of(s)
        if group[0][0] == "f" and group[0][6] is not None:          # a definition
            d = group[0]
            if not kept(d):
                continue
            name, brace = d[1], off(d[6])
            p = code.find("(", off(d[4]))
            k, depth = p, 0
            while 0 <= k < brace:
                depth += (code[k] == "(") - (code[k] == ")")
                k += 1
                if depth == 0:
                    break
            if p < 0 or not code[k:brace].strip():                   # no parameter declarations: no K&R
                stmt = _flat(code[s:brace]) + ";"
                out.append(Decl(rel, line, S.line_of(brace), name, "fdef", stmt, _name_at(stmt, name)))
                continue
            head, between = code[s:k], code[k:brace]
            types = {}
            for decl in between.split(";"):
                for n, dd in _data_decls(decl) or [] if decl.strip() else []:
                    types[n] = _flat(dd.removeprefix("extern ").rstrip(";"))
            params = [f"{promote} {n}" if promote else types.get(n, f"int {n}") for n, promote in d[7]]
            proto = _flat(code[s:p] + "(" + (", ".join(params) or "void") + ")") + ";"
            out.append(Decl(rel, line, S.line_of(brace), name, "knr", _flat(head + " " + between) + " {}",
                            _name_at(_flat(head), name), proto=proto))
            continue
        e, commas = stmt_end(s)
        last = S.line_of(e)
        base, texts = declarators(group, s, e, commas)
        if len(texts) != len(group):          # the text and the front end disagree (a declarator from a macro)
            continue
        if group[0][0] == "f":
            for d, t in zip(group, texts):
                if not kept(d):
                    continue
                stmt = _flat(base + " " + t) + ";" if len(group) > 1 else _flat(code[s:e]) + ";"
                fm = DECL.match(stmt)
                out.append(Decl(rel, line, last, d[1], "proto", stmt, fm.start(2) if fm and fm.group(2) == d[1]
                                else _name_at(stmt, d[1])))
            continue
        init = any(d[7] for d in group)
        base = re.sub(r"^\s*extern\b", "", base)
        for d, t in zip(group, texts):
            if not kept(d):
                continue
            decl = _flat("extern " + base + " " + t) + ";"
            if d[6] == "extern":
                decl = _flat(code[s:e]) + ";" if len(group) == 1 else decl
                out.append(Decl(rel, line, last, d[1], "extern", decl, _name_at(decl, d[1])))
            else:
                out.append(Decl(rel, line, last, d[1], "ddef", decl, _name_at(decl, d[1]), init=init))
    return out


IDENT = re.compile(r"[A-Za-z_]\w*")


def file_macros(rel: str, text: str, m: dict) -> list[tuple[str, int, str]]:
    """(name, line, `#define` line) of the macros the preprocessor defined in a file (its model's:
    srcscan.defines; comments blanked, continuations joined)."""
    S = srcscan.Source(rel, text)
    return [(d.name, d.line, "#define " + d.name + d.rest(S.code).replace("\\\n", " ")) for d in srcscan.defines(S, m)]


_scans: dict[tuple[str, str], tuple] = {}     # (file, sha256 of its text) -> (its declarations, its macros)


def scanned(rel: str, p: Path, m: dict) -> tuple[list[Decl], list]:
    """(the declarations, the macros) of one file, from its model (srcscan.models: the scan holds a model while
    the file's parse stands, so the model's identity names it; the entry keeps it alive)."""
    key = (rel, fsmemo.sha256(p), id(m))
    hit = _scans.get(key)
    if hit is None:
        if len(_scans) > 50000:
            _scans.clear()
        text = fsmemo.read_text(p)
        macros = file_macros(rel, text, m)
        decls = file_scope_decls(rel, text, m)
        hit = _scans[key] = (decls, macros, m)
    return hit[0], hit[1]


RENAME = re.compile(r"#define ([A-Za-z_]\w*)[ \t]+([A-Za-z_]\w*)[ \t]*$")
UNDEF_LINE = re.compile(r"^[ \t]*#[ \t]*undef[ \t]+([A-Za-z_]\w*)", re.M)


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


COPY, CHECK = "@dcp-copy", "@dcp-check"       # the pseudo files of the renamed copies and the type comparisons
TAG = re.compile(r"\b(struct|union)\s+([A-Za-z_]\w*)")
IDENTS = re.compile(r"[A-Za-z_]\w*")


@dataclass
class AllDecls:
    """The all-declarations unit: its text and what its lines stand for."""
    text: str
    headers: list                 # include/X.h, in include order
    decls: list                   # every Decl of the headers and the sources (definitions included)
    defs: dict                    # name -> the definition every other declaration is compared with
    copies: dict                  # copy id -> the Decl renamed __dcp_<id> on line <id> of COPY
    checks: dict                  # check id -> (Decl, its definition), line <id> of CHECK
    macros: dict                  # macro name -> file:line of the header that defines it (first)


SYSINC = re.compile(r'^[ \t]*#[ \t]*include[ \t]*<([^>]+)>', re.M)


_provided: dict[tuple, tuple] = {}


def provides(root: Path, rel: str, m: dict) -> tuple[set, set]:
    """_provides of a file, kept while its text and its model are the same (as scanned keeps its declarations)."""
    p = Path(root) / rel
    key = (rel, fsmemo.sha256(p), id(m))
    hit = _provided.get(key)
    if hit is None:
        if len(_provided) > 5000:
            _provided.clear()
        hit = _provided[key] = (*_provides(rel, fsmemo.read_text(p), m), m)
    return hit[0], hit[1]


def _provides(rel: str, text: str, m: dict) -> tuple[set, set]:
    """(the typedef names, tags with a body and macros a header defines, the identifiers it uses): the front end's
    typedefs, tags and live macros of the header's model; the identifiers are the words of its live code
    (srcscan.live_code: comments, strings, directives and skipped branches blanked; a tag's name not counted: a
    tag needs no definition to be named)."""
    S = srcscan.Source(rel, text)
    defined = {name for _, name in m["types"]} | {name for _, name, _ in m["macros"]}
    code = re.sub(r"\b(?:struct|union|enum)\s+[A-Za-z_]\w*", " ", srcscan.live_code(S, m))
    return defined, set(IDENTS.findall(code)) - defined


def header_order(root: Path, headers: list[str], models: dict) -> list[str]:
    """The headers in an order that defines a name before the headers that use it (by name, alphabetical
    among equals): what the units' own include order gives each of them, as far as names show it."""
    info = {h: provides(root, h, models.get(h, srcscan.EMPTY)) for h in headers}
    provider = {}
    for h in headers:
        for n in info[h][0]:
            provider.setdefault(n, h)
    # a header it includes itself counts too: it may use the name before its own #include (gildegold's ch.h
    # names D3ANIMSLOT 80 lines before it includes d3_anim.h), and the include guard makes the second a no-op
    deps = {h: {provider[n] for n in info[h][1] if n in provider} - {h} for h in headers}
    out, seen = [], set()

    def visit(h):
        stack = [(h, iter(sorted(deps[h])))]
        seen.add(h)
        while stack:
            cur, it = stack[-1]
            nxt = next((d for d in it if d not in seen), None)
            if nxt is None:
                stack.pop()
                out.append(cur)
            else:
                seen.add(nxt)
                stack.append((nxt, iter(sorted(deps[nxt]))))

    for h in headers:
        if h not in seen:
            visit(h)
    return out


_sysinc: dict[tuple, list] = {}         # (file, its text's hash) -> its #include <..> names


def system_includes(root: Path, files: list[str]) -> list[str]:
    """The `#include <..>` names of the files, first seen first (winsock2.h before windows.h)."""
    out = []
    for f in files:
        p = Path(root) / f
        key = (f, fsmemo.sha256(p))
        names = _sysinc.get(key)
        if names is None:
            if len(_sysinc) > 5000:
                _sysinc.clear()
            names = _sysinc[key] = [m.group(1).strip() for m in SYSINC.finditer(fsmemo.read_text(p))]
        for n in names:
            if n not in out:
                out.append(n)
    if "winsock2.h" in out:
        out.remove("winsock2.h")
        out.insert(0, "winsock2.h")
    if "windows.h" not in out:
        out.insert(1 if out[:1] == ["winsock2.h"] else 0, "windows.h")
    return out


def alldecls(root: Path, defines=()) -> AllDecls:
    """The all-declarations unit (module docstring, M5): windows.h, every header of include/ that is not
    private, the sources' file-scope prototypes and extern data (behind `#line`, with the macros of their unit
    that they use), then the sources' definitions (a function definition's head as a prototype, a K&R one with
    an empty body, a data definition as an extern declaration), then per symbol with a definition each other
    spelling of it renamed and compared with the definition by `__builtin_types_compatible_p`. `defines`: the
    macros of the target's compile, as its units are parsed (the headers' models are the source scan's then)."""
    root = Path(root)
    inc, src = root / "include", root / "src"
    private = private_headers(root)
    headers = [f"include/{h.name}" for h in sorted(inc.glob("*.h")) if h.name not in private] if inc.exists() else []
    fmodels = srcscan.models(root, srcscan.project_files(root), defines)
    headers = header_order(root, headers, fmodels)
    srcs = ["src/" + rel for rel, _ in fsmemo.walk(src, ("*.c",))] if src.exists() else []
    hdecls = [d for h in headers for d in scanned(h, root / h, fmodels.get(h, srcscan.EMPTY))[0] if not d.definition]
    sources = [("src/" + rel, *scanned("src/" + rel, p, fmodels.get("src/" + rel, srcscan.EMPTY)))
               for rel, p in fsmemo.walk(src, ("*.c",))] if src.exists() else []
    defs = {}
    for rel, ds, _ in sources:
        for d in ds:
            if d.definition:
                cur = defs.get(d.name)
                if cur is None or (cur.kind == d.kind == "ddef" and d.init and not cur.init):
                    defs[d.name] = d
    every = hdecls + [d for _, ds, _ in sources for d in ds]
    chosen = {id(d) for d in defs.values()}
    compared = {id(d) for d in every if d.name in defs and id(d) not in chosen and d.spelling != defs[d.name].spelling}
    need_def = {d.name for d in every if id(d) in compared}
    copies, checks, copy_of = {}, {}, {}
    lines = [f"#if __has_include(<{n}>)\n#include <{n}>\n#endif" for n in system_includes(root, headers + srcs)]
    tags = sorted({m.group(0) for d in every for m in TAG.finditer(d.stmt)})
    lines += [f"{t};" for t in tags]               # a tag first named in a prototype is the file's, not the prototype's
    lines += [f'#include "{Path(h).name}"' for h in headers]

    def copy(d):
        k = len(copies) + 1
        copies[k] = d
        copy_of[id(d)] = k
        lines.append(f'#line {k} "{COPY}"')
        lines.append(d.renamed(f"__dcp_{k}"))

    for d in hdecls:
        if id(d) in compared:
            copy(d)
    knr_done = set()
    for definitions in (False, True):
        for rel, ds, macros in sources:
            mine = [d for d in ds if d.definition == definitions]
            if not mine:
                continue
            avail = {name: (rel, line, text) for name, line, text in macros}
            used, todo = {}, {w for d in mine for w in IDENTS.findall(d.stmt)}
            while todo:
                w = todo.pop()
                if w in avail and w not in used:
                    used[w] = avail[w]
                    todo |= set(IDENTS.findall(avail[w][2][len("#define "):])) - set(used)
            used = sorted(used.items(), key=lambda kv: (kv[1][0], kv[1][1]))     # by place: the text is the cache key
            for name, (mrel, line, text) in used:
                lines += [f'#pragma push_macro("{name}")', f"#undef {name}", f'#line {line} "{mrel}"', text]
            for d in mine:
                if d.kind == "knr" and d.name in knr_done:
                    pass                                   # a second K&R definition: only its renamed copy
                else:
                    knr_done.add(d.name) if d.kind == "knr" else None
                    lines.append(f'#line {d.line} "{rel}"')
                    lines.append(d.stmt)
                if id(d) in compared or (id(d) in chosen and d.name in need_def):
                    copy(d)
            for name, _ in reversed(used):
                lines += [f"#undef {name}", f'#pragma pop_macro("{name}")']
    for d in every:
        if id(d) in compared:
            k = len(checks) + 1
            ref = defs[d.name]
            checks[k] = (d, ref)
            lines.append(f'#line {k} "{CHECK}"')
            lines.append(f"typedef char __dcp_c{k}[__builtin_types_compatible_p(__typeof__(&__dcp_{copy_of[id(d)]}), "
                         f"__typeof__(&__dcp_{copy_of[id(ref)]})) ? 1 : -1];")
    macros = {}
    for h in headers:
        for name, line, _ in scanned(h, root / h, fmodels.get(h, srcscan.EMPTY))[1]:
            macros.setdefault(name, f"{h}:{line}")
    return AllDecls("\n".join(lines) + "\n", headers, every, defs, copies, checks, macros)


def alldecls_text(root: Path, defines=()) -> str:
    return alldecls(root, defines).text


def _cast_view(d: Decl) -> str | None:
    """The cast macro that gives a unit its own view of a symbol, from that view's spelling: a function as a
    pointer cast, data as a dereferenced pointer cast of its address."""
    s = d.spelling
    k = _name_at(s, d.name)
    if k < 0:
        return None
    if d.func:
        ret, rest = s[:k].strip(), s[k + len(d.name):].strip()
        cc = re.search(r"\s*\b(__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)$", ret)
        inner = f"({cc.group(1)} *)" if cc else "(*)"
        ret = ret[:cc.start()] if cc else ret
        return f"#define {d.name}_X (({ret} {inner}{rest}){d.name})"
    if re.search(r"[\[(]", s[k:]):
        return None
    return f"#define {d.name}_X (*({s[:k].strip()} *)&{d.name})"


def _locs(ds, cap=8) -> str:
    ws = [d.where if isinstance(d, Decl) else d for d in ds]
    return ", ".join(ws[:cap]) + (f" (+{len(ws) - cap})" if len(ws) > cap else "")


def _by_spelling(ds) -> str:
    groups = {}
    for d in ds:
        groups.setdefault(d.spelling, []).append(d)
    return "; ".join(f"`{sp}` at {_locs(g)}" for sp, g in groups.items())


def _exempt(lines: "Lines", d: Decl) -> bool:
    return any(lines.exempt(d.file, n) for n in range(d.line, d.last + 1))


def cross_conflicts(ad: AllDecls, diags: list, lines: "Lines") -> list[str]:
    """The M5 lines of one run over the all-declarations unit: one per symbol declared unlike its definition
    (or, without a definition in src/, unlike its first declaration), one per header that does not compile
    there, one per tag or typedef two headers define differently."""
    groups = grouped(diags)
    bad_copy, negative, bad_check, errlines, header_errs = set(), set(), set(), set(), {}
    cross = []
    for g in groups:
        d = g[0]
        if d["kind"] != "error":
            continue
        for x in g:
            if x["file"] == COPY:
                bad_copy.add(x["line"])
        if d["file"] == CHECK:
            (negative if "negative size" in d["msg"] else bad_check).add(d["line"])
            continue
        if d["file"] == COPY:
            continue
        if CROSS.match(d["msg"]):
            cross.append(g)
            continue
        errlines.add((d["file"], d["line"]))
        if d["file"].startswith("include/"):
            header_errs.setdefault(d["file"], []).append(d)
    copy_id = {id(d): k for k, d in ad.copies.items()}
    out = []
    # per symbol with a definition: every spelling compared with it
    verdicts: dict[str, dict] = {}
    for k, (d, ref) in ad.checks.items():
        v = verdicts.setdefault(d.name, {"disagree": [], "unknown": [], "agree": []})
        if copy_id[id(ref)] in bad_copy:
            v["undecided"] = True
        if copy_id[id(d)] in bad_copy or k in bad_check:
            v["unknown"].append(d)
        else:
            v["disagree" if k in negative else "agree"].append(d)
    decided = set()
    by_name = {}
    for d in ad.decls:
        by_name.setdefault(d.name, []).append(d)
    for name, v in sorted(verdicts.items()):
        ref = ad.defs[name]
        if v.get("undecided"):
            continue                       # its definition uses a type of its unit: clang's pairs decide below
        decided.add(name)
        same = [d for d in by_name[name] if d is not ref and d.spelling == ref.spelling]
        agree = same + v["agree"]
        exempt = [d for d in v["disagree"] if d.file.startswith("src/") and _exempt(lines, d)]
        dis = [d for d in v["disagree"] if d not in exempt]
        if not dis:
            continue
        unit = Path(ref.file).stem if ref.file.startswith("src/") else "?"
        s = (f"{dis[0].where}: {name} declared unlike its definition {ref.where} (unit {unit}) `{ref.spelling}`"
             + (f" (as a prototype `{ref.proto[:-1]}`)" if ref.proto else "") + ": "
             f"disagree={len(dis)} {_by_spelling(dis)}; agree={len(agree)}" + (f" {_locs(agree)}" if agree else "")
             + (f"; unknown={len(v['unknown'])} {_locs(v['unknown'])} (a type of its unit)" if v["unknown"] else "")
             + (f"; exempt={len(exempt)} {_locs(exempt)}" if exempt else ""))
        broken = [d for d in dis if any((d.file, n) in errlines for n in range(d.line, d.last + 1))]
        if broken:
            s += f" / {_locs(broken)} has an error of its own here: its verdict may be clang's recovery"
        marked = [d for d in dis if d.file.startswith("include/") and _exempt(lines, d)]
        if marked:
            view = _cast_view(marked[0])
            s += (f" / the @original spelling is in a header ({marked[0].where}): a header repeats the definition's "
                  f"spelling `{ref.proto or ref.spelling + ';'}` (unit {unit}); a unit's own view goes in its head region as a cast macro"
                  + (f": `{view} /* @original why */`" if view else ""))
        out.append(s)
    # clang's pairs: symbols without a definition (or one with a type of its unit), tags and typedefs
    at = {}
    for d in ad.decls:
        at.setdefault((d.file, d.line), d)
        at.setdefault((d.file, d.line, d.name), d)
    rd = {}

    def spelling(x, name=None):
        d = at.get((x["file"], x["line"], name)) or at.get((x["file"], x["line"]))
        if d is not None:
            return d.spelling
        f = x["file"]
        if f not in rd:
            p = Path(lines.root) / f
            rd[f] = p.read_text(errors="replace").split("\n") if p.exists() else []
        ls = rd[f]
        return _flat(ls[x["line"] - 1]).split("/*")[0].strip().removeprefix("extern ").rstrip(";") if 0 < x["line"] <= len(ls) else None

    pairs: dict[str, list] = {}
    for g in cross:
        d = g[0]
        name = d.get("name") if CROSS.match(d["msg"]).group(2) else None
        if name in decided:
            continue
        if any((x["file"], x["line"]) in errlines for x in g):
            continue                       # one side does not compile: clang's recovery, not a disagreement
        if len(g) > 1 and spelling(d, name) is not None and spelling(d, name) == spelling(g[1], name) and "{" not in (spelling(d, name) or "{"):
            continue                       # textually one declaration: a recovery artefact
        in_headers = all(x["file"].startswith("include/") for x in g)
        hint = None
        if any(lines.exempt(x["file"], x["line"]) for x in g):
            if not in_headers:
                continue
            ref = ad.defs.get(name)
            hint = (" / the @original spelling is in a header: two headers that cannot be included together; "
                    + (f"a header repeats the definition's spelling `{ref.proto or ref.spelling + ';'}` (unit {ref.file.split('/')[1]}), "
                       if ref is not None else "")
                    + "a unit's own view goes in its head region as a cast macro (`#define name_X ((T (*)(..))name) /* @original why */`)")
        pairs.setdefault(name or "?", []).append((g, hint))
    for name, ps in sorted(pairs.items()):
        xs = [at.get((g[0]["file"], g[0]["line"], name)) for g, _ in ps]
        first = at.get((ps[0][0][1]["file"], ps[0][0][1]["line"], name)) if len(ps[0][0]) > 1 else None
        hints = list(dict.fromkeys(h for _, h in ps if h))
        if name in by_name and first is not None and all(xs):
            dis = list(dict.fromkeys(xs))
            ref = ad.defs.get(name)
            agree = [d for d in by_name[name] if d not in dis and d is not first and d is not ref]
            out.append(f"{dis[0].where}: {name} declared differently"
                       + (f" (its definition {ref.where} `{ref.spelling}` uses a type of its unit: not compared)" if ref
                          else ", no definition in src/") + f": against its first declaration {first.where} "
                       f"`{first.spelling}`: disagree={len(dis)} {_by_spelling(dis)}; agree={len(agree)}"
                       + (f" {_locs(agree)}" if agree else "") + f" (clang: {ps[0][0][0]['msg']})" + "".join(hints))
        elif len(ps) == 1:
            out.append(fmt_group(ps[0][0]) + "".join(hints))
        else:
            out.append(f"{ps[0][0][0]['file']}:{ps[0][0][0]['line']}: {name}: {len(ps)} conflicts: "
                       + " | ".join(fmt_group(g) for g, _ in ps) + "".join(hints))
    for h, es in sorted(header_errs.items()):
        e = es[0]
        text = spelling(dict(e, file=e["file"])) or ""
        clash = [f"{w} is a macro of {ad.macros[w]}" for w in dict.fromkeys(IDENTS.findall(text))
                 if w in ad.macros and not ad.macros[w].startswith(h + ":")]
        if clash:
            e = dict(e, msg=e["msg"] + " (" + "; ".join(clash[:3]) + ")")
        advice = ("a macro of another header rewrites its text: the two headers cannot be included together; keep "
                  "one spelling of the name (the macro or the declaration)" if clash else
                  "it is included after the system headers the sources include and the headers that define the names "
                  "it uses: include or declare what it uses")
        out.append(f"{e['file']}:{e['line']}: {h} does not compile in the all-declarations unit ({len(es)} errors, "
                   f"first: {e['msg']}): its declarations are not compared and their conflicts hidden; {advice}")
    return out


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
        ad = alldecls(root, defines)
    text = ad.text
    akey = sha256("alldecls", VERSION, *clang, text, *defines,
                  *(fsmemo.sha256(p) for p in sorted((Path(root) / "include").glob("*.h"))) if (Path(root) / "include").exists() else "")
    cross = st.blob_json(akey)
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
            cross = diags
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
        conflicts = cross_conflicts(ad, cross, lines)
    conflicts += private_violations(root, private_headers(root))
    res = {"units": {a.unit: a.src_hash for a in units_},
           "includes": {a.unit: (tus.get(a.unit) or {}).get("include_hash", "") for a in units_}, "errors": sorted(set(errors)), "cross": sorted(set(conflicts)),
           "calls": {k: [list(c) for c in sorted(set(v))] for k, v in sorted(calls.items())}}
    st.set_meta("lint", canonical(res))
    project.forget_input("lint")
    return dict(res, parsed=len(jobs), cached=len(units_) - len(jobs))
