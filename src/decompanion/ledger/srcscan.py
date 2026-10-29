"""The source scan: the sources are typed state, and this module reads it (a port of the address-comment parser
of the first attempt, rea/tools/gildegold/core/gen.py). No object file is needed: it reads text.

Layout of a target project's sources
  src/<unit>/head.c        includes, local types, prototypes, leading file-scope data; no function
  src/<unit>/f_<addr>.c    one function, plus the file-scope definitions that precede it in TU order
  src/<unit>/u_<name>.c    one function the binary does not contain (`/* unlinked, why */`)
  src/<unit>/order         optional: the unit's translation-unit order when it is not the address order (CL
                           compiles a caller differently once a callee is defined above it, and a declaration
                           must precede its use): `#` reason lines first, then every fragment file of the
                           unit (f_<addr>.c and u_<name>.c), one per line, in TU order (check L12)
  include/<unit>.h         public prototypes and extern declarations
  `__inline` helpers       not functions of the binary (no symbol, no address): head.c, any fragment or a
                           header may define them where the TU needs them; the scan does not count them

Address comments
  function   the FIRST line of its fragment:  /* 0x10001000, what it does */
             several targets:                  /* server:0x10001000, exe:0x4a3000, what it does */
             (a bare address is the default target's; the file name carries the first address listed)
             not in the binary:                /* unlinked, why */
             tags inside it:                   @deep why   @stuck why   @rough
  data       after the definition / extern:    int x = 1;  /* 0x1002a000 */
             one address per declarator:       extern int a, b;  /* 0x1002a000, 0x1002a004 */
             a multi-line table:               the comment on the line above it
             (the same target prefixes; `/* unlinked, why */` for data the binary lacks)
  placeholders  an identifier that spells an address (`Unk10001000`, `FUN_10001000`, `name_10001000`) must
             name a real start (check L5, rules/layout.py)

scan(root) returns every definition, data declaration, placeholder and parse error of the tree, for all
targets; the loader rule L.src (rules/layout.py) picks the current target's addresses and emits the facts.
Results are memoised per tree hash, so the loader and the checks parse once per process.
"""
from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from .. import fsmemo

TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)
DEF = re.compile(r"^[A-Za-z_][^\n;{}#]*?\b([A-Za-z_]\w*)\s*\(", re.M)
ADDR_ITEM = r"(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+"
LEAD_ADDRS = re.compile(r"^\s*(" + ADDR_ITEM + r")((?:\s*[,/]\s*" + ADDR_ITEM + r")*)")
ONE_ADDR = re.compile(r"(?:([A-Za-z][A-Za-z0-9_-]*):)?(0x[0-9a-fA-F]+)")
UNLINKED = re.compile(r"^\s*unlinked\b\s*,?\s*(.*)", re.S)
DEEP = re.compile(r"@deep\b[ \t]*(.*?)[ \t]*(?:\*/|\n|$)")
STUCK = re.compile(r"@stuck\b[ \t]*(.*?)[ \t]*(?:\*/|\n|$)")
ROUGH = re.compile(r"@rough\b")
FUNCPTR = re.compile(r"\(\s*(?:__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)?\s*\*+\s*(?:const\s+)?([A-Za-z_]\w*)\s*\)")
PLACEHOLDER_ADDR = re.compile(r"\b[A-Za-z_]\w*?(?:Unk|FUN_|DAT_|PTR_|LAB_)([0-9a-fA-F]{5,8})\b"
                              r"|\b[A-Za-z_]\w*?_((?=[0-9a-fA-F]*\d)[0-9a-fA-F]{6,8})\b")
STATIC = re.compile(r"\s*(?:(?:const|volatile)\s+)*static\b")
INLINE = re.compile(r"\b(?:__inline|__forceinline|inline)\b")
KNR = re.compile(r"^[^=(;]*\b[A-Za-z_]\w*\s*\([^()]*\)\s*[A-Za-z_][^;]*;\s*$")
DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(([^)]*)\)[ \t]*((?:\\\n|[^\n])*)", re.M)
DESCRIBED = re.compile(r"\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?(0x[0-9a-fA-F]+)\b\s*(.*)", re.S)
FRAGMENT = re.compile(r"^f_([0-9a-fA-F]+)\.c$")
UNLINKED_FRAGMENT = re.compile(r"^u_([A-Za-z_]\w*)\.c$")
QUALIFIERS = {"extern", "static", "const", "volatile", "unsigned", "signed", "int", "char", "short", "long", "float",
              "double", "void", "struct", "union", "enum", "register", "far", "near", "__cdecl", "__stdcall"}


@dataclass(frozen=True)
class Function:
    file: str                 # project-relative posix path
    line: int                 # line of the definition
    unit: str
    name: str
    addrs: tuple              # ((target or None, address), ...) in comment order
    unlinked: bool
    what: str                 # the description after the addresses
    deep: str | None = None
    stuck: str | None = None
    rough: bool = False
    comment_line: int = 1
    static: bool = False      # `static`: its name is the unit's own (N2 compares it within the unit only)


@dataclass(frozen=True)
class Data:
    file: str
    line: int
    unit: str
    name: str
    kind: str                 # def | extern
    addrs: tuple              # ((target or None, address), ...) of this declarator
    unlinked: bool
    static: bool = False      # `static`: its name is the unit's own (N2 compares it within the unit only)


@dataclass(frozen=True)
class Placeholder:
    file: str
    line: int
    ident: str
    value: int


@dataclass(frozen=True)
class ScanError:
    file: str
    line: int
    check: str                # L.src | L11 | L12
    message: str


@dataclass
class Scan:
    functions: list[Function] = field(default_factory=list)
    data: list[Data] = field(default_factory=list)
    placeholders: list[Placeholder] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    files: int = 0
    orders: dict[str, list[str]] = field(default_factory=dict)   # unit -> fragment file names in TU order
    macros: list[tuple[str, str]] = field(default_factory=list)  # (name, body) of every function-like #define
    described: list[int] = field(default_factory=list)          # addresses an address comment describes in words


def lead_addrs(body: str) -> list[tuple[str | None, int]]:
    """The addresses a comment starts with: `0x10001000` / `server:0x10001000, exe:0x4a3000, what`."""
    m = LEAD_ADDRS.match(body)
    if not m:
        return []
    return [(t or None, int(a, 16)) for t, a in ONE_ADDR.findall(m.group(0))]


def lead_end(body: str) -> int:
    m = LEAD_ADDRS.match(body)
    return m.end() if m else 0


@functools.lru_cache(maxsize=256)
def blank_alternatives(code: str) -> str:
    """The code with every preprocessor line blanked, and the text of `#else` / `#elif` / `#if 0` branches blanked
    too (their braces need not balance); offsets unchanged."""
    out = []
    stack = []
    cont = False
    for line in code.split("\n"):
        m = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b\s*(.*)", line)
        blank = any(stack)
        if m:
            d, arg = m.group(1), m.group(2).strip()
            if d in ("if", "ifdef", "ifndef"):
                stack.append(d == "if" and arg == "0")
            elif d in ("elif", "else") and stack:
                stack[-1] = True
            elif d == "endif" and stack:
                stack.pop()
            blank = True
        elif line.lstrip().startswith("#") or cont:
            blank = True
        cont = blank and line.rstrip("\r").endswith("\\")
        out.append("".join(" " if c != "\r" else c for c in line) if blank else line)
    return "\n".join(out)


class Source:
    """One .c / .h file: its comments, its code with strings and comments blanked, its definitions and data."""

    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self._line_starts = None
        self._own_line_ends = None
        self.comments = []            # (start, end, body)
        out = []
        pos = 0
        for m in TOKEN.finditer(text):
            out.append(text[pos:m.start()])
            tok = m.group(0)
            if tok.startswith("/*"):
                self.comments.append((m.start(), m.end(), tok[2:-2]))
            elif tok.startswith("//"):
                self.comments.append((m.start(), m.end(), tok[2:]))
            out.append("".join("\n" if c == "\n" else " " for c in tok))
            pos = m.end()
        out.append(text[pos:])
        self.code = "".join(out)

    def line_of(self, off: int) -> int:
        if self._line_starts is None:
            self._line_starts = [0] + [i + 1 for i, c in enumerate(self.text) if c == "\n"]
        return bisect.bisect_right(self._line_starts, off)

    def end_before(self, off: int) -> int:
        text = self.text
        while off > 0 and text[off - 1].isspace():
            off -= 1
        return off

    def own_line_comment_ends(self) -> dict[int, int]:
        """end offset -> index of every comment that starts its line."""
        if self._own_line_ends is None:
            self._own_line_ends = {e: i for i, (s, e, b) in enumerate(self.comments)
                                   if not self.text[self.text.rfind("\n", 0, s) + 1:s].strip()}
        return self._own_line_ends

    def definitions(self) -> list[tuple[int, str]]:
        """[(offset, name)] of every function definition (a `name(...)` followed by `{`, K&R parameter
        declarations allowed in between), in file order; `__inline` definitions are no functions of the
        binary and are left out."""
        res = []
        code = blank_alternatives(self.code)
        for m in DEF.finditer(code):
            k = m.end()
            depth = 1
            while k < len(code) and depth:
                depth += (code[k] == "(") - (code[k] == ")")
                k += 1
            if depth:
                continue
            brace = code.find("{", k)
            if brace < 0 or brace - k > 4000:
                continue
            between = code[k:brace]
            if "=" in between or ")" in between:
                continue
            params = set(re.findall(r"[A-Za-z_]\w*", code[m.end():k - 1]))
            chunks = between.split(";")
            if len(chunks) > 1 and (chunks[-1].strip() or not all(
                    re.findall(r"[A-Za-z_]\w*", c) and set(re.findall(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:,|$)", c.strip())) <= params
                    and set(re.findall(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:,|$)", c.strip())) for c in chunks[:-1])):
                continue
            if chunks[-1].strip():
                continue
            if INLINE.search(code, m.start(), m.start(1)):
                continue
            res.append((m.start(), m.group(1)))
        return res

    def data(self, skip_comment: int | None = None):
        """[(offset, name, kind, [(target, addr)], unlinked)] of every file-scope data declaration (kind extern:
        a declaration; def: a definition, static, initialised or tentative). The addresses come from a comment
        on the declaration's first line or right after its `;`, else from the own-line comment directly above
        it (never from comment `skip_comment`, the fragment's function address comment). With several
        declarators, the comment's addresses go one per declarator (per target)."""
        code = blank_alternatives(self.code)
        res = []
        ends = self.own_line_comment_ends()
        cstarts = [c[0] for c in self.comments]
        n = len(code)
        i = 0
        while i < n:
            while i < n and code[i].isspace():
                i += 1
            if i >= n:
                break
            s = i
            depth = brace = 0
            opened = -1
            while i < n:
                c = code[i]
                if c in "([":
                    depth += 1
                elif c in ")]":
                    depth -= 1
                elif c == "{":
                    if brace == 0 and opened < 0:
                        opened = i
                    brace += 1
                elif c == "}":
                    brace -= 1
                    if brace == 0 and depth == 0 and (opened == s or code[s:opened].rstrip().endswith(")")):
                        i += 1
                        break
                elif c == ";" and depth == 0 and brace == 0:
                    i += 1
                    break
                i += 1
            stmt = code[s:i]
            if not stmt.rstrip().endswith(";"):
                continue
            if KNR.match(stmt):
                b = code.find("{", i)
                d = 0
                while 0 <= b < n:
                    d += code[b] == "{"
                    d -= code[b] == "}"
                    b += 1
                    if not d:
                        break
                i = b if b > 0 else n
                continue
            head = stmt.rstrip()[:-1]
            d = 0
            k = -1
            for j, c in enumerate(head):
                d += c in "([{"
                d -= c in ")]}"
                if c == "=" and d == 0:
                    head, k = head[:j], j
                    break
            is_extern = head.lstrip().startswith("extern")
            if head.lstrip().startswith("typedef"):
                continue
            body = "{" in head
            if body:
                head = head[head.rfind("}") + 1:]
                if not head.strip():
                    continue
            while re.search(r"\[[^\[\]]*\]", head):
                head = re.sub(r"\[[^\[\]]*\]", "", head)
            fp = FUNCPTR.search(head)
            if "(" in head and (fp is None or fp.start() != head.find("(")):
                continue
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
            idents = []
            for j, ch in enumerate(chunks):
                m = FUNCPTR.search(ch)
                if m:
                    idents.append(m.group(1))
                    continue
                ws = re.findall(r"[A-Za-z_]\w*", ch)
                if j == 0 and not body and (len(ws) < 2 or ws[-1] in QUALIFIERS or (len(ws) == 2 and ws[0] in ("struct", "union", "enum"))):
                    idents = []
                    break
                if not ws or ws[-1] in QUALIFIERS:
                    idents = []
                    break
                idents.append(ws[-1])
            if not idents:
                continue
            kind = "extern" if is_extern and k < 0 else "def"
            addrs: list = []
            unlinked = False
            eol = code.find("\n", s)
            after = i
            while after < len(self.text) and self.text[after] in " \t":
                after += 1
            for ci in range(bisect.bisect_left(cstarts, s), len(cstarts)):
                cs = cstarts[ci]
                on_first_line = cs < eol if eol >= 0 else True
                if not (on_first_line or i <= cs <= after):
                    if cs > after:
                        break
                    continue
                if ci == skip_comment:
                    continue
                addrs = lead_addrs(self.comments[ci][2])
                unlinked = unlinked or bool(UNLINKED.match(self.comments[ci][2]))
                if addrs:
                    break
            if not addrs:
                e = self.end_before(s)
                if e in ends and ends[e] != skip_comment:
                    addrs = lead_addrs(self.comments[ends[e]][2])
                    unlinked = unlinked or bool(UNLINKED.match(self.comments[ends[e]][2]))
            per_decl = assign(addrs, len(idents))
            for j, name in enumerate(idents):
                res.append((s, name, kind, per_decl[j], unlinked))
        return res


def assign(addrs: list, n: int) -> list[tuple]:
    """Split a comment's addresses over n declarators: per target, either one address per declarator or (one
    declarator) all of them. A list that fits neither gives every declarator nothing."""
    if n == 1:
        return [tuple(addrs)]
    by_t: dict = {}
    for t, a in addrs:
        by_t.setdefault(t, []).append(a)
    if any(len(v) != n for v in by_t.values()):
        return [()] * n
    return [tuple((t, v[j]) for t, v in by_t.items()) for j in range(n)]


def unit_of(rel: str) -> str:
    parts = rel.split("/")
    if parts[0] == "src" and len(parts) >= 3:
        return parts[1]
    return Path(rel).stem


def scan_file(rel: str, text: str, out: Scan):
    S = Source(rel, text)
    for m in DEFINE.finditer(S.text):
        out.macros.append((m.group(1), m.group(3)))
    for s, e, body in S.comments:
        m = DESCRIBED.match(body)
        if m:
            rest = re.split(r"@(?:deep|stuck|rough)\b", m.group(2))[0]
            rest = re.sub(r"^(?:\s*[,/]\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+)*", "", rest)
            if rest.strip(" \t\r\n,.-:;*/"):
                out.described.extend(a for _, a in lead_addrs(body))
    name = Path(rel).name
    unit = unit_of(rel)
    in_src = rel.startswith("src/")
    is_fragment = in_src and bool(FRAGMENT.match(name) or UNLINKED_FRAGMENT.match(name))
    defs = S.definitions()
    skip = None
    if in_src and rel.endswith(".c") and not is_fragment and name not in ("head.c", "tail.c"):
        out.errors.append(ScanError(rel, 1, "L.src", f"unexpected source file {name}: a unit holds head.c, f_<addr>.c "
                                                     f"and u_<name>.c fragments, and tail.c"))
    if is_fragment:
        if len(defs) != 1:
            out.errors.append(ScanError(rel, 1, "L.src", f"a fragment defines exactly one function, this one {len(defs)}"))
        first = S.comments[0] if S.comments else None
        if first is None or first[0] != 0 and text[:first[0]].strip():
            out.errors.append(ScanError(rel, 1, "L.src", "the first line is not the function's address comment"))
            first = None
        elif S.line_of(first[0]) != 1:
            out.errors.append(ScanError(rel, S.line_of(first[0]), "L.src", "the address comment is not on the first line"))
            first = None
        if first is not None and defs:
            skip = 0
            body = first[2]
            addrs = lead_addrs(body)
            um = UNLINKED.match(body)
            off, fname = defs[-1]
            what = (um.group(1) if um else body[lead_end(body):]).strip().lstrip(",").strip()
            what = re.sub(r"\s+", " ", re.split(r"@(?:deep|stuck|rough)\b", what)[0]).strip()
            dm, sm = DEEP.search(body), STUCK.search(body)
            fm, um_name = FRAGMENT.match(name), UNLINKED_FRAGMENT.match(name)
            if not addrs and not um:
                out.errors.append(ScanError(rel, 1, "L.src", "the first comment holds neither an address nor `unlinked`"))
            elif addrs and fm and int(fm.group(1), 16) != addrs[0][1]:
                out.errors.append(ScanError(rel, 1, "L11", f"the file name says {int(fm.group(1), 16):#x}, the address comment "
                                                           f"{addrs[0][1]:#x}"))
            elif addrs and um_name:
                out.errors.append(ScanError(rel, 1, "L11", "an u_<name>.c fragment holds an unlinked function; this one has an address"))
            elif um and fm:
                out.errors.append(ScanError(rel, 1, "L11", "an unlinked function lives in u_<name>.c, not f_<addr>.c"))
            elif um and um_name and um_name.group(1) != fname:
                out.errors.append(ScanError(rel, 1, "L11", f"the file name says {um_name.group(1)}, the definition {fname}"))
            out.functions.append(Function(rel, S.line_of(off), unit, fname, tuple(addrs), bool(um) and not addrs, what,
                                          dm.group(1).strip() if dm else None, sm.group(1).strip() if sm else None,
                                          bool(ROUGH.search(body)), static=bool(STATIC.match(S.code, off))))
    elif defs:
        for off, fname in defs:
            out.errors.append(ScanError(rel, S.line_of(off), "L.src", f"function {fname} defined outside a fragment "
                                                                       f"(src/<unit>/f_<addr>.c)"))
    for off, dname, kind, addrs, unlinked in S.data(skip):
        out.data.append(Data(rel, S.line_of(off), unit, dname, kind, addrs, unlinked, bool(STATIC.match(S.code, off))))
    seen = set()
    for m in PLACEHOLDER_ADDR.finditer(S.code):
        ident = m.group(0)
        if ident in seen:
            continue
        seen.add(ident)
        out.placeholders.append(Placeholder(rel, S.line_of(m.start()), ident, int(m.group(1) or m.group(2), 16)))


_cache: dict[tuple[str, str], Scan] = {}
_files: dict[tuple[str, str], Scan] = {}          # (path, sha256 of the text) -> that file's own scan
CACHE_VERSION = 2                                  # bump when scan_file's results change


def _file_cache(root: Path) -> tuple[Path | None, dict]:
    """The on-disk memo of per-file scans (build/cache/srcscan.pickle), {} when absent or of another version."""
    import pickle
    d = root / "build"
    if not d.is_dir():
        return None, {}
    path = d / "cache" / "srcscan.pickle"
    try:
        version, data = pickle.loads(path.read_bytes())
        return path, data if version == CACHE_VERSION else {}
    except (OSError, ValueError, EOFError, pickle.UnpicklingError, TypeError):
        return path, {}


def scan(root: Path, tree_hash: str | None = None) -> Scan:
    """Scan src/**/*.c, src/**/*.h and include/**/*.h of the project at root (memoised per tree hash). Each
    file's own scan is memoised by its path and the hash of its text, in the process and in
    build/cache/srcscan.pickle, so an edit re-parses only the files it changed."""
    import hashlib
    import pickle
    root = Path(root)
    if tree_hash is not None and (str(root), tree_hash) in _cache:
        return _cache[(str(root), tree_hash)]
    out = Scan()
    path, disk = _file_cache(root)
    used, changed = {}, False
    for d, pats in (("src", ("*.c", "*.h")), ("include", ("*.h",))):
        base = root / d
        if not base.exists():
            continue
        files = sorted({p for pat in pats for p in base.rglob(pat)})
        for p in files:
            rel = p.relative_to(root).as_posix()
            text = fsmemo.read_text(p)
            key = (rel, fsmemo.sha256(p))
            piece = _files.get(key) or disk.get(key)
            if piece is None:
                piece = Scan()
                scan_file(rel, text, piece)
                changed = True
            _files[key] = used[key] = piece
            out.files += 1
            out.functions += piece.functions
            out.data += piece.data
            out.placeholders += piece.placeholders
            out.errors += piece.errors
            out.macros += piece.macros
            out.described += piece.described
    if path is not None and (changed or len(used) != len(disk)):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(pickle.dumps((CACHE_VERSION, used)))
            tmp.replace(path)
        except OSError:
            pass
    src = root / "src"
    if src.exists():
        for p in sorted(src.glob("*/order")):
            scan_order(p.relative_to(root).as_posix(), p.read_text(errors="replace"),
                       sorted(q.name for q in p.parent.glob("*.c")), out)
    if tree_hash is not None:
        _cache[(str(root), tree_hash)] = out
    return out


def scan_order(rel: str, text: str, files: list[str], out: Scan):
    """src/<unit>/order: `#` reason lines, then each fragment file of the unit once, in TU order (L12)."""
    unit = unit_of(rel)
    names, seen, reason = [], set(), False
    for n, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            reason = reason or bool(s.lstrip("#").strip())
            continue
        if not reason:
            out.errors.append(ScanError(rel, n, "L12", "an order file starts with its reason (`# why`)"))
            reason = True
        if not (FRAGMENT.match(s) or UNLINKED_FRAGMENT.match(s)):
            out.errors.append(ScanError(rel, n, "L12", f"{s} is no fragment file (f_<addr>.c, u_<name>.c)"))
        elif s not in files:
            out.errors.append(ScanError(rel, n, "L12", f"{s}: no such file in src/{unit}"))
        elif s in seen:
            out.errors.append(ScanError(rel, n, "L12", f"{s} listed twice"))
        else:
            seen.add(s)
            names.append(s)
    missing = [f for f in files if (FRAGMENT.match(f) or UNLINKED_FRAGMENT.match(f)) and f not in seen]
    if missing:
        out.errors.append(ScanError(rel, 1, "L12", f"the order leaves out {len(missing)} fragment(s): " + ", ".join(missing[:6])))
    out.orders[unit] = names


def address_for(addrs: tuple, target: str, default: str) -> int | None:
    """The address of a (target or None, address) list for one target (a bare address is the default's)."""
    for t, a in addrs:
        if (t or default) == target:
            return a
    return None
