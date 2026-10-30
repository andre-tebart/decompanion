"""The C compiler of today as the declaration checker of the sources (lifted from the first attempt's
decomp/decl/lint.py). clang parses every translation unit the way VC6 sees it (the amalgamation with its
`#line` directives, MS compatibility, C89 so that `T f();` is a K&R declaration, the toolchain's own headers as
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
      view goes into that unit (a cast macro in its head.c). A header marked `@private UNIT[,..]` in its first
      20 lines (the original only included it into those units) is left out of the unit, and a file outside
      those units that includes it is an M5 error
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

import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .. import fsmemo
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
# M5: a symbol declared differently in two files of the all-declarations unit; a struct / union / enum or
# typedef defined twice counts too (two headers that define one tag cannot be included together)
CROSS = re.compile(r"(?:conflicting types for|redeclaration of|redefinition of|typedef redefinition with different "
                   r"types) ('(\w+)'|\()")
KEYWORDS = {"return", "else", "goto", "case", "sizeof", "if", "while", "for", "switch", "do", "typedef", "default"}
DEFAULT_CLANG = "C:/Program Files/LLVM/bin/clang.exe"
VERSION = "4"


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


def _knr_prototype(head: str, between: str, name: str) -> str:
    """The prototype a K&R definition's parameter declarations spell (`int` for an undeclared one): a K&R
    definition's own type has no parameters to compare."""
    m = re.search(r"\b" + re.escape(name) + r"\s*\(", head)
    k = m.end() - 1 if m else head.find("(")
    params = [w.strip() for w in head[k + 1:head.rfind(")")].split(",") if w.strip()]
    types = {}
    for decl in between.split(";"):
        if not decl.strip():
            continue
        for n, d in _data_decls(decl) or []:
            types[n] = d.removeprefix("extern ").rstrip(";").strip()
    return _flat(head[:k] + "(" + (", ".join(types.get(n, f"int {n}") for n in params) or "void") + ")") + ";"


def file_scope_decls(rel: str, text: str) -> list[Decl]:
    """Every file-scope declaration and definition of a function or data object that is not static, in file
    order: prototypes (`proto`), extern data (`extern`), function definitions (`fdef` as a prototype of their
    head, `knr` a K&R definition with an empty body) and data definitions (`ddef`, as an extern declaration).
    Typedefs, tags, `__inline` bodies and function pointer types are left out."""
    S = srcscan.Source(rel, text)
    code = srcscan.blank_alternatives(S.code)
    data = {}
    for off, name, kind, _, _ in S.data():
        data.setdefault(off, []).append((name, kind))
    defs = []                                      # (offset, name, offset after the parameter list, its brace)
    for off, name in S.definitions():
        m = re.compile(r"\b" + re.escape(name) + r"\s*\(").search(code, off)
        if not m:
            continue
        k, depth = m.end(), 1
        while k < len(code) and depth:
            depth += (code[k] == "(") - (code[k] == ")")
            k += 1
        defs.append((off, name, k, code.find("{", k)))
    out = []
    n = len(code)

    def first(s):
        while s < n and code[s].isspace():
            s += 1
        return s

    def add_stmt(start, end):
        s = first(start)
        stmt = code[s:end]
        if not stmt.strip() or srcscan.STATIC.match(stmt) or re.match(r"\s*typedef\b", stmt):
            return
        line, last = S.line_of(s), S.line_of(end)
        m = DECL.match(stmt)
        if m and "=" not in stmt[:m.end()] and not any(t in KEYWORDS for t in re.findall(r"[A-Za-z_]\w*", m.group(1))):
            flat = _flat(stmt)
            head = flat[:flat.find("(")]
            close, depth = -1, 0
            for j in range(flat.find("("), len(flat)):
                depth += (flat[j] == "(") - (flat[j] == ")")
                if depth == 0:
                    close = j
                    break
            if close < 0 or flat[close + 1:].strip():
                return                     # `f(a, b) int a;`: a K&R head the definition scan did not take
            if "(*" not in flat[:flat.find("(") + 2] and "*)" not in head:
                fm = DECL.match(flat)
                out.append(Decl(rel, line, last, fm.group(2), "proto", flat + ";", fm.start(2)))
            return
        items = data.get(s)
        if not items:
            return
        made = _data_decls(stmt, [nm for nm, _ in items])
        if made is None:
            return
        kind = items[0][1]
        for nm, decl in made:
            if kind == "extern":
                decl = _flat(stmt) + ";" if len(made) == 1 else decl
                out.append(Decl(rel, line, last, nm, "extern", decl, _name_at(decl, nm)))
            else:
                out.append(Decl(rel, line, last, nm, "ddef", decl, _name_at(decl, nm), init="=" in stmt))

    di, cur, start, p, b, opened, extern_c = 0, None, 0, 0, 0, -1, 0
    i = 0
    while i < n:
        while di < len(defs) and defs[di][0] <= i:
            cur = defs[di]
            di += 1
        c = code[i]
        if c in "([":
            p += 1
        elif c in ")]":
            p -= 1
        elif c == "{":
            if b == 0 and p == 0 and code[start:i].strip() == "extern":        # extern "C" { (the string blanked)
                extern_c += 1
                start = i + 1
                i += 1
                continue
            if b == 0:
                opened = i
            b += 1
        elif c == "}":
            if b == 0 and extern_c:
                extern_c -= 1
                start = i + 1
            else:
                b -= 1
                if b == 0 and p == 0:
                    if cur is not None and start <= cur[0] < opened and cur[3] == opened:
                        off, name, k, brace = cur
                        s = first(start)
                        head, between = code[s:k], code[k:brace]
                        if not srcscan.STATIC.match(head):
                            line = S.line_of(s)
                            if between.strip():
                                stmt = _flat(head + " " + between) + " {}"
                                out.append(Decl(rel, line, S.line_of(brace), name, "knr", stmt, _name_at(_flat(head), name),
                                                proto=_knr_prototype(code[s:k], between, name)))
                            else:
                                stmt = _flat(head) + ";"
                                out.append(Decl(rel, line, S.line_of(brace), name, "fdef", stmt, _name_at(stmt, name)))
                        cur = None
                        start = i + 1
                    elif code[start:opened].rstrip().endswith((")", ";")) or not code[start:opened].strip():
                        start = i + 1              # an __inline body, a block without a head: no declaration
        elif c == ";" and b == 0 and p == 0:
            if cur is not None and start <= cur[0] < i < cur[3]:              # a K&R parameter declaration
                pass
            else:
                add_stmt(start, i)
                start = i + 1
        i += 1
    return out


def file_scope_prototypes(rel: str, text: str) -> list[tuple[int, str]]:
    """(line, statement) of every file-scope function declaration that is no definition, not static and no
    function pointer."""
    return [(d.line, d.stmt) for d in file_scope_decls(rel, text) if d.kind == "proto"]


MACRO_LINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)((?:\\\n|[^\n])*)", re.M)


def file_macros(rel: str, text: str) -> list[tuple[str, int, str]]:
    """(name, line, `#define` line) of the macros a file defines (comments blanked, continuations joined)."""
    S = srcscan.Source(rel, text)
    return [(m.group(1), S.line_of(m.start()), "#define " + m.group(1) + m.group(2).replace("\\\n", " "))
            for m in MACRO_LINE.finditer(S.code)]


_scans: dict[tuple[str, str], tuple] = {}     # (file, sha256 of its text) -> (its declarations, its macros)


def scanned(rel: str, p: Path) -> tuple[list[Decl], list]:
    key = (rel, fsmemo.sha256(p))
    hit = _scans.get(key)
    if hit is None:
        if len(_scans) > 50000:
            _scans.clear()
        text = fsmemo.read_text(p)
        hit = _scans[key] = (file_scope_decls(rel, text), file_macros(rel, text))
    return hit


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
        text = fsmemo.read_text(p)
        for m in INCLUDE_LINE.finditer(text):
            h = Path(m.group(1)).name
            units = private.get(h)
            if units is None:
                continue
            if rel.startswith("src/"):
                ok = rel.split("/")[1] in units
            else:
                ok = Path(rel).name == h or private.get(Path(rel).name, {None}) <= units
            if not ok:
                line = text.count("\n", 0, m.start()) + 1
                out.append(f"{rel}:{line}: includes {h}, private to {','.join(sorted(units))} (@private in the header)")
    return out


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
TYPEDEF_NAME = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$")
TAG_BODY = re.compile(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{")


def _provides(rel: str, text: str) -> tuple[set, set]:
    """(the typedef names, tags with a body and macros a header defines, the identifiers it uses)."""
    S = srcscan.Source(rel, text)
    code = srcscan.blank_alternatives(S.code)
    defined = {m.group(1) for m in MACRO_LINE.finditer(S.code)} | {m.group(1) for m in TAG_BODY.finditer(code)}
    for m in re.finditer(r"\btypedef\b", code):
        end, depth = m.end(), 0
        while end < len(code) and not (code[end] == ";" and depth == 0):
            depth += (code[end] in "({") - (code[end] in ")}")
            end += 1
        stmt = code[m.end():end]
        while re.search(r"\{[^{}]*\}", stmt):
            stmt = re.sub(r"\{[^{}]*\}", "", stmt)
        chunks, depth, cur = [], 0, ""
        for c in stmt:
            depth += (c == "(") - (c == ")")
            if c == "," and depth == 0:
                chunks.append(cur)
                cur = ""
            else:
                cur += c
        for chunk in chunks + [cur]:
            fp = srcscan.FUNCPTR.search(chunk)
            t = fp or TYPEDEF_NAME.search(chunk.strip())
            if t:
                defined.add(t.group(1))
    code = re.sub(r"\b(?:struct|union|enum)\s+[A-Za-z_]\w*", " ", code)      # a tag needs no definition to be named
    return defined, set(IDENTS.findall(code)) - defined


def header_order(root: Path, headers: list[str]) -> list[str]:
    """The headers in an order that defines a name before the headers that use it (by name, alphabetical
    among equals): what the units' own include order gives each of them, as far as names show it."""
    texts = {h: fsmemo.read_text(Path(root) / h) for h in headers}
    info = {h: _provides(h, texts[h]) for h in headers}
    provider = {}
    for h in headers:
        for n in info[h][0]:
            provider.setdefault(n, h)
    known = {Path(h).name: h for h in headers}
    includes = {h: {known[Path(m.group(1)).name] for m in INCLUDE_LINE.finditer(texts[h]) if Path(m.group(1)).name in known}
                for h in headers}
    within = {}                                    # a header and what it includes, transitively

    def closure(h):
        if h not in within:
            within[h] = {h}
            for b in includes[h]:
                within[h] |= closure(b)
        return within[h]

    deps = {}
    for h in headers:
        # what a header includes itself comes in at its place; one included by another comes after its includer
        need = {provider[n] for n in info[h][1] if n in provider} - closure(h)
        deps[h] = need | {a for a in headers if h in includes[a] and a != h}
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


def system_includes(root: Path, files: list[str]) -> list[str]:
    """The `#include <..>` names of the files, first seen first (winsock2.h before windows.h)."""
    out = []
    for f in files:
        for m in SYSINC.finditer(fsmemo.read_text(Path(root) / f)):
            n = m.group(1).strip()
            if n not in out:
                out.append(n)
    if "winsock2.h" in out:
        out.remove("winsock2.h")
        out.insert(0, "winsock2.h")
    if "windows.h" not in out:
        out.insert(1 if out[:1] == ["winsock2.h"] else 0, "windows.h")
    return out


def alldecls(root: Path) -> AllDecls:
    """The all-declarations unit (module docstring, M5): windows.h, every header of include/ that is not
    private, the sources' file-scope prototypes and extern data (behind `#line`, with the macros of their unit
    that they use), then the sources' definitions (a function definition's head as a prototype, a K&R one with
    an empty body, a data definition as an extern declaration), then per symbol with a definition each other
    spelling of it renamed and compared with the definition by `__builtin_types_compatible_p`."""
    root = Path(root)
    inc, src = root / "include", root / "src"
    private = private_headers(root)
    headers = [f"include/{h.name}" for h in sorted(inc.glob("*.h")) if h.name not in private] if inc.exists() else []
    headers = header_order(root, headers)
    srcs = ["src/" + rel for rel, _ in fsmemo.walk(src, ("*.c",))] if src.exists() else []
    hdecls = [d for h in headers for d in scanned(h, root / h)[0] if not d.definition]
    sources = [("src/" + rel, *scanned("src/" + rel, p)) for rel, p in fsmemo.walk(src, ("*.c",))] if src.exists() else []
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
    by_unit_macros = {}
    for rel, ds, macros in sources:
        if rel.endswith("/head.c"):
            by_unit_macros[rel.split("/")[1]] = (rel, macros)
    knr_done = set()
    for definitions in (False, True):
        for rel, ds, macros in sources:
            mine = [d for d in ds if d.definition == definitions]
            if not mine:
                continue
            unit = rel.split("/")[1]
            avail = {}
            for mrel, ms in ([by_unit_macros[unit]] if unit in by_unit_macros and by_unit_macros[unit][0] != rel else []) + [(rel, macros)]:
                for name, line, text in ms:
                    avail[name] = (mrel, line, text)
            used, todo = {}, {w for d in mine for w in IDENTS.findall(d.stmt)}
            while todo:
                w = todo.pop()
                if w in avail and w not in used:
                    used[w] = avail[w]
                    todo |= set(IDENTS.findall(avail[w][2][len("#define "):])) - set(used)
            for name, (mrel, line, text) in sorted(used.items(), key=lambda kv: (kv[1][0], kv[1][1])):
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
            for name in used:
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
        for name, line, _ in scanned(h, root / h)[1]:
            macros.setdefault(name, f"{h}:{line}")
    return AllDecls("\n".join(lines) + "\n", headers, every, defs, copies, checks, macros)


def alldecls_text(root: Path) -> str:
    return alldecls(root).text


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
        unit = ref.file.split("/")[1] if ref.file.startswith("src/") else "?"
        s = (f"{dis[0].where}: {name} declared unlike its definition {ref.where} (unit {unit}) `{ref.spelling}`: "
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
                  f"spelling `{ref.spelling};` (unit {unit}); a unit's own view goes in its head.c as a cast macro"
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
        m = CROSS.match(d["msg"])
        name = m.group(2)
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
                    + (f"a header repeats the definition's spelling `{ref.spelling};` (unit {ref.file.split('/')[1]}), "
                       if ref is not None else "")
                    + "a unit's own view goes in its head.c as a cast macro (`#define name_X ((T (*)(..))name) /* @original why */`)")
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
        out.append(f"{e['file']}:{e['line']}: {h} does not compile in the all-declarations unit ({len(es)} errors, "
                   f"first: {e['msg']}): its declarations are not compared and their conflicts hidden; it is included "
                   "after the system headers the sources include and the headers that define the names it uses: "
                   "include or declare what it uses")
    return out


def stale(project) -> list[str] | None:
    """The units whose source or include set changed since the last lint (by the compile's hashes), None when
    there was no lint run: the lint result (Q7, M5..M7) is current exactly when this is empty."""
    m = project.store.meta("lint")
    if m is None:
        return None
    m = json.loads(m)
    units, includes = m.get("units", {}), m.get("includes", {})
    tus = project.store.tus()
    changed = {u for u, row in tus.items() if units.get(u) != row["src_hash"] or includes.get(u) != row["include_hash"]}
    return sorted(changed | (set(units) - set(tus)))


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
        inc = (tus.get(a.unit) or {}).get("include_hash", "")
        key = sha256("lint", VERSION, a.src_hash, canonical(FLAGS), inc, canonical([str(d) for d in sysdirs]))
        hit = st.blob_json(key)
        if hit is None:
            B.A.write(root, a)                            # clang reads it
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
    ad = alldecls(root)
    text = ad.text
    akey = sha256("alldecls", VERSION, text, canonical(FLAGS), canonical([str(d) for d in sysdirs]),
                  *(fsmemo.sha256(p) for p in sorted((Path(root) / "include").glob("*.h"))) if (Path(root) / "include").exists() else "")
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
    conflicts = cross_conflicts(ad, cross, lines)
    conflicts += private_violations(root, private_headers(root))
    res = {"units": {a.unit: a.src_hash for a in amalgs},
           "includes": {a.unit: (tus.get(a.unit) or {}).get("include_hash", "") for a in amalgs}, "errors": sorted(set(errors)), "cross": sorted(set(conflicts)),
           "calls": {k: sorted(set(v)) for k, v in sorted(calls.items())}}
    st.set_meta("lint", canonical(res))
    project.forget_input("lint")
    return dict(res, parsed=len(jobs), cached=len(amalgs) - len(jobs))
