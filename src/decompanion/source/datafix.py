"""The data tooling (`dcp data map`, `dcp data fix`): a reading view of a unit's data and the rewrites that
answer the data checks of rules/match_data.py (lifted in idea from the first attempt's tools/data_defs.py and
tools/data_trim.py, which rewrote sources from address gaps; here every rewrite answers one conflict and is
verified by a build).

The model (data_model): every data declaration of the sources with an address (srcscan) joined with the facts
of its address: the `global` symbol M.data.site / .content / .draft placed (level, extent, section kind, size)
and the next start of any symbol after it (the room it has); the conflicts D1 / D4 / D5 at it.

The fixes, each the answer the check itself names:
  D5  a tentative definition `T x;` in the original's uninitialised data gets `= 0` (a pointer or a basic
      type) or `= {0}` (anything else: an array, a struct, a typedef the scan cannot see through; C allows
      braces around a scalar initialiser too), so VC6 places it in its unit's .bss in declaration order
      instead of LINK's common area.
  D1  an array whose extent overlaps the next symbol: its first dimension shrinks to the room up to that
      symbol, when the room is a whole number of elements; `extern` declarations of the same name with the
      old dimension follow.
  D4  the definitions of one unit and section kind not in address order (VC6 places them in definition
      order): the longest run already in address order stays, every other definition moves in front of the
      definition that follows it in address order (or behind the last one before it), with its own-line
      comment and trailing comment (also one that runs on over the following lines); a non-static
      definition that moves below its old place leaves `extern T x;` there for the uses in between; a
      definition that would move above a type, macro or declaration it uses (defined in between) is left
      for a human (the move would not compile; move that one first). A
      statement with several declarators is left for a human.
A fix that the scan cannot apply exactly (no such statement, no array, a room that is no whole number of
elements, several declarators) is listed as `manual` with the reason.

Speed: one scan of the sources (memoised by tree hash), one pass over the store's symbols and conflicts, and
every file a run reads is tokenised once (Files). `--write` compiles once for the whole batch, and once more
only for the units it reverts.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..ledger import srcscan
from ..ledger.fact import Kind

BASIC = {"char", "short", "int", "long", "float", "double", "unsigned", "signed", "void", "__int8", "__int16",
         "__int32", "__int64", "BYTE", "WORD", "DWORD", "BOOL", "UINT", "ULONG", "LONG", "HANDLE", "HWND"}
SKIP = {"static", "const", "volatile", "extern", "register"}
CHECKS = ("D5", "D1", "D4")


@dataclass
class DataDef:
    unit: str
    name: str
    file: str
    line: int
    kind: str                  # def | extern
    addr: int
    static: bool
    level: str = "-"           # proven / declared, from the `global` symbol at addr
    extent: str = "-"          # site / content / draft
    section: str = "-"         # data / rdata / bss / common, the object's section kind
    size: int | None = None
    next_start: int | None = None
    conflicts: list = field(default_factory=list)   # (check, message) of the errors at it
    warnings: list = field(default_factory=list)    # (check, message) of the warnings at it


def data_model(p) -> list[DataDef]:
    """Every data declaration of the current target with an address, joined with its facts (module docstring)."""
    st = p.store
    sc = srcscan.scan(p.root, p.input_hash("src"))
    default = p.default_target
    out = []
    for d in sc.data:
        a = srcscan.address_for(d.addrs, p.target_name, default)
        if a is not None:
            out.append(DataDef(d.unit, d.name, d.file, d.line, d.kind, a, d.static))
    glob, starts = {}, set()
    code = [(s.va, s.end) for s in p.image.sections if s.holds_code]
    for f in st.facts(Kind.symbol):
        sk = f.value.get("skind")
        if sk == "unknown.data" or any(lo <= f.lo < hi for lo, hi in code):
            continue
        starts.add(f.lo)
        if sk == "global":
            glob.setdefault(f.lo, f)
    starts = sorted(starts)
    by_addr: dict[int, list] = {}
    for c in st.conflicts():
        if c.check in CHECKS or c.check == "M.data.content":
            by_addr.setdefault(c.lo, []).append(c)
    for d in out:
        g = glob.get(d.addr)
        if g is not None and d.kind == "def":
            d.level, d.extent = g.level.name, g.value.get("extent", "-")
            d.section = g.value.get("kind", "-")
            d.size = g.hi - g.lo if g.value.get("extent") != "draft" or g.hi - g.lo > 1 else None
        i = bisect.bisect_right(starts, d.addr)
        d.next_start = starts[i] if i < len(starts) else None
        for c in by_addr.get(d.addr, []):
            if c.a == f"src:{d.file}:{d.line}" or c.check == "D4":
                (d.conflicts if c.severity.value in ("error", "bug") else d.warnings).append((c.check, c.message))
    return out


# ------------------------------------------------------------------------------------------------ statements
class Files:
    """The texts of the files a run reads, each tokenised once (srcscan.Source and its line-start table): a run
    touches many definitions of few files."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.texts: dict[str, str] = {}
        self._parsed: dict[str, tuple] = {}
        self._models: dict[str, dict | None] = {}

    def text(self, rel: str) -> str:
        t = self.texts.get(rel)
        if t is None:
            t = self.texts[rel] = (self.root / rel).read_text(errors="replace")
        return t

    def model(self, rel: str) -> dict | None:
        """The front end's model of the file (srcscan.model_of), None for a file the scan does not hold."""
        if rel not in self._models:
            self._models[rel] = srcscan.model_of(self.root, rel, self.text(rel))
        return self._models[rel]

    def parsed(self, rel: str):
        """(Source, line starts) of the file."""
        hit = self._parsed.get(rel)
        if hit is None:
            text = self.text(rel)
            hit = self._parsed[rel] = (srcscan.Source(rel, text), [0] + [i + 1 for i, c in enumerate(text) if c == "\n"])
        return hit


@dataclass
class Stmt:
    file: str
    start: int                 # the block: own-line comment above, the statement, its trailing comment, newline
    end: int
    s0: int                    # the statement itself
    s1: int                    # just past its `;`


def statement_at(files: Files, rel: str, line: int) -> Stmt | None:
    """The declaration statement starting on `line` of `rel` (1-based), with its block (module docstring)."""
    text = files.text(rel)
    S, starts = files.parsed(rel)
    if line - 1 >= len(starts):
        return None
    code = S.code
    s0 = starts[line - 1]
    while s0 < len(code) and code[s0] in " \t":
        s0 += 1
    depth, i = 0, s0
    while i < len(code):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            break
        i += 1
    if i >= len(code):
        return None
    s1 = i + 1
    eol = text.find("\n", s1)
    eol = len(text) if eol < 0 else eol
    after = s1
    for cs, ce, _ in S.comments:                  # a trailing comment may run on over the following lines
        if s1 <= cs < eol:
            after = max(after, ce)
    end = text.find("\n", after)
    end = len(text) if end < 0 else end + 1
    if code[after:end].strip():                   # code after the `;` on its line: the block ends at the `;`
        end = s1
    start = starts[line - 1]
    name = Path(rel).name
    fragment = bool(srcscan.FRAGMENT.match(name) or srcscan.UNLINKED_FRAGMENT.match(name))
    k = S.end_before(start)
    ci = S.own_line_comment_ends().get(k)
    if ci is not None and not (fragment and ci == 0) and text.count("\n", k, start) <= 1:
        start = text.rfind("\n", 0, S.comments[ci][0]) + 1
    return Stmt(rel, start, end, s0, s1)


@dataclass
class Declarator:
    name_end: int
    dims_end: int
    dims: list
    before: str                # the statement's text before the name (the type)
    has_init: bool
    count: int                 # declarators in the statement
    end: int                   # the end of the whole declarator (before a `,` `;` or `=` at the statement's top level)
    aggregate: bool | None = None   # an array, struct or union (the front end's type; None: not known)


def declarator(files: Files, st: Stmt, name: str) -> Declarator | None:
    """The declarator of `name` in a statement: the name where the front end's model has it (its type's class
    too), else its first whole-word occurrence; its dimensions and its end read from the text."""
    S = files.parsed(st.file)[0]
    code = S.code
    seg = code[st.s0:st.s1]
    m = files.model(st.file)
    group = [d for d in m["decls"] if d[0] == "v" and st.s0 <= S.offset(*d[3]) < st.s1] if m is not None else []
    hit = next((d for d in group if d[1] == name), None)
    if hit is not None:
        start, aggregate, count = S.offset(*hit[4]) - st.s0, hit[8], len(group)
    else:
        mm = re.search(r"\b" + re.escape(name) + r"\b", seg)
        if mm is None:
            return None
        start, aggregate, count = mm.start(), None, None
    name_end = start + len(name)
    k, dims = name_end, []
    while True:
        j = k
        while j < len(seg) and seg[j] in " \t\n":
            j += 1
        if j < len(seg) and seg[j] == "[":
            e = seg.find("]", j)
            dims.append(seg[j + 1:e].strip())
            k = e + 1
            continue
        break
    depth, commas, end, init = 0, 0, None, False
    for j, c in enumerate(seg):
        if c in ",;=" and depth == 0 and j >= k and end is None:
            end, init = j, c == "="
        depth += c in "([{"
        depth -= c in ")]}"
        commas += c == "," and depth == 0
    end = len(seg) - 1 if end is None else end
    while end > k and seg[end - 1] in " \t\n":
        end -= 1
    return Declarator(st.s0 + name_end, st.s0 + k, dims, seg[:start], init, count or commas + 1, st.s0 + end,
                      aggregate)


# ------------------------------------------------------------------------------------------------ the edits
@dataclass
class Edit:
    file: str
    at: int                    # offset in the original text
    remove: int                # characters removed at `at`
    insert: str
    why: str                   # one line: the check and the symbol
    unit: str
    group: str = ""            # the edits that stand or fall together (a D4 move: its removal and insertion)


def d5_edits(files: Files, model) -> tuple[list[Edit], list[str]]:
    edits, manual = [], []
    for d in model:
        if not any(c == "D5" for c, _ in d.conflicts):
            continue
        st = statement_at(files, d.file, d.line)
        dc = st and declarator(files, st, d.name)
        if not dc:
            manual.append(f"D5 {d.name} {d.file}:{d.line}: the statement is not found")
            continue
        if dc.has_init:
            manual.append(f"D5 {d.name} {d.file}:{d.line}: it has an initialiser already")
            continue
        words = set(re.findall(r"[A-Za-z_]\w*", dc.before)) - SKIP
        scalar = (not dc.aggregate if dc.aggregate is not None else
                  not dc.dims and ("*" in dc.before or "(" in dc.before or (words and words <= BASIC)))
        init = " = 0" if scalar else " = {0}"
        edits.append(Edit(d.file, dc.end, 0, init, f"D5 {d.name}{init.strip()} ({d.addr:#x})", d.unit, f"D5 {d.name}"))
    return edits, manual


def d1_edits(files: Files, model) -> tuple[list[Edit], list[str]]:
    edits, manual = [], []
    externs: dict[str, list] = {}
    for d in model:
        if d.kind == "extern":
            externs.setdefault(d.name, []).append(d)
    for d in model:
        if d.kind != "def" or not any(c == "D1" for c, _ in d.conflicts):
            continue
        if d.size is None or d.next_start is None:
            manual.append(f"D1 {d.name} {d.file}:{d.line}: no size or next symbol known")
            continue
        room = d.next_start - d.addr
        st = statement_at(files, d.file, d.line)
        dc = st and declarator(files, st, d.name)
        if not dc:
            manual.append(f"D1 {d.name} {d.file}:{d.line}: the statement is not found")
            continue
        if not dc.dims or not dc.dims[0].isdigit():
            manual.append(f"D1 {d.name} {d.file}:{d.line}: {d.size} bytes, room {room}: no array with a literal first "
                          f"dimension to shrink")
            continue
        old = int(dc.dims[0])
        elem = d.size // old if old else 0
        if not elem or d.size % old or room % elem or room // elem < 1:
            manual.append(f"D1 {d.name} {d.file}:{d.line}: {d.size} bytes in {old} elements, room {room} is no whole "
                          f"number of elements")
            continue
        new = room // elem
        if new >= old:
            manual.append(f"D1 {d.name} {d.file}:{d.line}: room {room} holds {new} elements, not fewer than {old}")
            continue
        code = files.parsed(d.file)[0].code
        b = code.index("[", dc.name_end)
        edits.append(Edit(d.file, b + 1, code.index("]", b) - b - 1, str(new),
                          f"D1 {d.name}[{old}] -> [{new}] ({d.addr:#x}, room {room})", d.unit, f"D1 {d.name}"))
        for x in externs.get(d.name, []):
            xs = statement_at(files, x.file, x.line)
            xd = xs and declarator(files, xs, d.name)
            if xd and xd.dims and xd.dims[0] == str(old):
                xc = files.parsed(x.file)[0].code
                xb = xc.index("[", xd.name_end)
                edits.append(Edit(x.file, xb + 1, xc.index("]", xb) - xb - 1, str(new),
                                  f"D1 {d.name} extern [{old}] -> [{new}] ({x.file}:{x.line})", d.unit, f"D1 {d.name}"))
    return edits, manual


def lis(seq: list[int]) -> set[int]:
    """Indices of one longest strictly increasing subsequence of seq (patience sorting, n log n)."""
    tails, tail_idx, prev = [], [], [None] * len(seq)
    for i, v in enumerate(seq):
        k = bisect.bisect_left(tails, v)
        if k == len(tails):
            tails.append(v)
            tail_idx.append(i)
        else:
            tails[k] = v
            tail_idx[k] = i
        prev[i] = tail_idx[k - 1] if k else None
    out, i = set(), tail_idx[-1] if tail_idx else None
    while i is not None:
        out.add(i)
        i = prev[i]
    return out


C_WORDS = {"auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern",
           "float", "for", "goto", "if", "int", "long", "register", "return", "short", "signed", "sizeof", "static",
           "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "__int8", "__int16",
           "__int32", "__int64", "__cdecl", "__stdcall", "__fastcall", "__declspec"}


def defined_in(code: str, idents: set[str]) -> str | None:
    """The first of `idents` that the (comment-blanked) code defines or declares: a macro, a typedef name, a
    struct / union / enum tag, an enum constant, a variable or function declaration. None when none is."""
    for x in sorted(idents):
        e = re.escape(x)
        pats = (rf"#\s*define\s+{e}\b",
                rf"\btypedef\b[^;]*?\b{e}\s*(?:\[[^\]]*\]\s*)*;", rf"\btypedef\b[^;]*\(\s*\*\s*{e}\s*\)",
                rf"\b(?:struct|union|enum)\s+{e}\s*\{{", rf"\}}\s*{e}\s*[;,]",
                rf"[{{,]\s*{e}\s*(?:=[^,}}]*)?[,}}]",
                rf"\b[A-Za-z_][\w \t\*]*\b{e}\s*(?:\[[^\]]*\]\s*)*(?:=|;|,|\()")
        if any(re.search(p, code) for p in pats):
            return x
    return None


def defined_between(files: Files, order: list[str], a: tuple[str, int], b: tuple[str, int], idents: set[str]) -> str | None:
    """The first of `idents` (by name) the unit defines or declares from position a (file, offset) up to position
    b, in amalgamation order: a macro, typedef, tag, enum constant or declaration of the files' models starting
    on a line in between; the text (defined_in over `between`) when a file has no model."""
    rank = {f: i for i, f in enumerate(order)}
    (fa, oa), (fb, ob) = a, b
    seq = [fa] if fa == fb else [fa] + order[rank[fa] + 1:rank[fb]] + [fb]
    found = set()
    for f in seq:
        m = files.model(f)
        if m is None:
            return defined_in(between(files, order, a, b), idents)
        S = files.parsed(f)[0]
        lo = S.line_of(oa) if f == fa else 1
        hi = S.line_of(ob) if f == fb else float("inf")
        names = ([(ln, n) for ln, n in m["types"]] + [(ln, n) for ln, n, _ in m["macros"]]
                 + [(d[3][0], d[1]) for d in m["decls"]])
        found |= {n for ln, n in names if lo <= ln < hi and n in idents}
    return min(found) if found else None


def between(files: Files, order: list[str], a: tuple[str, int], b: tuple[str, int]) -> str:
    """The comment-blanked code of the unit from position a (file, offset) up to position b, in amalgamation
    order (a before b)."""
    rank = {f: i for i, f in enumerate(order)}
    (fa, oa), (fb, ob) = a, b
    if fa == fb:
        return files.parsed(fa)[0].code[oa:ob]
    parts = [files.parsed(fa)[0].code[oa:]]
    parts += [files.parsed(f)[0].code for f in order[rank[fa] + 1:rank[fb]]]
    parts.append(files.parsed(fb)[0].code[:ob])
    return "\n".join(parts)


def d4_edits(files: Files, model, unit_order: dict[str, list[str]]) -> tuple[list[Edit], list[str]]:
    """unit_order: unit -> its part files in amalgamation order."""
    edits, manual = [], []
    groups: dict[tuple, list] = {}
    for d in model:
        if d.kind == "def" and d.section in ("data", "rdata", "bss"):
            groups.setdefault((d.unit, d.section), []).append(d)
    flagged = {d.unit for d in model if any(c == "D4" for c, _ in d.conflicts)}
    for (unit, sec), ds in sorted(groups.items()):
        if unit not in flagged:
            continue
        rank = {f: i for i, f in enumerate(unit_order.get(unit, []))}
        ds.sort(key=lambda d: (rank.get(d.file, len(rank)), d.line))
        if [d.addr for d in ds] == sorted(d.addr for d in ds):
            continue
        keep = lis([d.addr for d in ds])
        anchors = sorted((ds[i] for i in keep), key=lambda d: d.addr)
        moved = sorted((ds[i] for i in range(len(ds)) if i not in keep), key=lambda d: d.addr)
        for d in moved:
            st = statement_at(files, d.file, d.line)
            dc = st and declarator(files, st, d.name)
            if not dc:
                manual.append(f"D4 {d.name} {d.file}:{d.line}: the statement is not found")
                continue
            if dc.count > 1:
                manual.append(f"D4 {d.name} {d.file}:{d.line}: a statement with several declarators")
                continue
            later = [a for a in anchors if a.addr > d.addr]
            t = later[0] if later else anchors[-1]
            tst = statement_at(files, t.file, t.line)
            at = tst.start if later else tst.end
            up = (rank.get(t.file, len(rank)), at) < (rank.get(d.file, len(rank)), st.start)
            if up and t.file in rank and d.file in rank:
                code = files.parsed(d.file)[0].code
                used = set(re.findall(r"[A-Za-z_]\w*", code[st.s0:st.s1])) - C_WORDS - {d.name}
                x = defined_between(files, unit_order[unit], (t.file, at), (d.file, st.start), used)
                if x is not None:
                    manual.append(f"D4 {d.name} {d.file}:{d.line}: it uses {x}, which the unit defines between "
                                  f"{t.file} (before {t.name}) and its place; move {x} up first")
                    continue
            block = files.text(d.file)[st.start:st.end]
            if not block.endswith("\n"):
                block += "\n"
            # moving down past its uses: a non-static definition leaves its declaration behind (`extern T x[n];`,
            # no storage, so the unit's placement is unchanged); a static one has no such declaration in C
            stay = ""
            if (rank.get(t.file, len(rank)), at) > (rank.get(d.file, len(rank)), st.start) and not d.static:
                stay = "extern " + files.text(d.file)[st.s0:dc.end] + ";\n"
            edits.append(Edit(d.file, st.start, st.end - st.start, stay, f"D4 {d.name} ({d.addr:#x}) moves", unit, f"D4 {d.name}"))
            edits.append(Edit(t.file, at, 0, block, f"D4 {d.name} ({d.addr:#x}) {'before' if later else 'after'} "
                                                    f"{t.name} ({t.addr:#x}, {t.file}:{t.line})", unit, f"D4 {d.name}"))
    return edits, manual


def apply(files: Files, edits: list[Edit]) -> dict[str, str]:
    """The new texts of the files the edits touch (edits on the original offsets; at one offset a removal goes
    before an insertion, so an inserted block never falls into a removed one, and insertions keep the order
    the edits list them in)."""
    out = {}
    seq = {id(e): k for k, e in enumerate(edits)}
    for rel in sorted({e.file for e in edits}):
        text = files.text(rel)
        for e in sorted((e for e in edits if e.file == rel), key=lambda e: (e.at, 0 if not e.remove else 1, seq[id(e)]), reverse=True):
            text = text[:e.at] + e.insert + text[e.at + e.remove:]
        out[rel] = text
    return out


def byte_functions(p) -> dict[int, str]:
    """address -> unit of every function graded byte."""
    return {f.lo: f.value.get("unit", "") for f in p.store.facts(Kind.grade)
            if f.value.get("of") == "function" and f.value.get("code") == "byte"}


def failed_units(p) -> set[str]:
    return {f.value["tu"] for f in p.store.facts(Kind.build) if not f.value["ok"]}


# ------------------------------------------------------------------------------------------------ trial compiles
class Trial:
    """Compiles a unit with edits that are not written yet and compares its functions with the image: the
    amalgamation composed from the edited texts (amalg.compose's reader), one compiler run into
    build/obj/trial/, every fragment of the unit compared as M.match compares it (match/compare.py). A
    unit's edits are accepted together when the unit compiles and keeps every byte match; else each group
    is tried alone (in parallel) and the groups that pass on their own are tried together, then added one at
    a time while the unit stays whole. Nothing touches the sources or the store."""

    def __init__(self, p):
        from ..build import compile as B
        from ..match import compare as C
        self.p, self.B, self.C = p, B, C
        self.img, self.tc = p.image, p.toolchain
        self.amalgs = {a.unit: a for a in B.plan(p)}
        st = p.store
        self.relocs = sorted(f.lo for f in st.facts(Kind.ref) if f.value["rkind"] == "reloc") or None
        if not self.img.relocations():
            self.relocs = None
        s = {f.lo for f in st.facts(Kind.start)}
        s |= {f.lo for f in st.facts(Kind.symbol) if f.value.get("skind") in ("func", "thunk") and f.level.name != "open"}
        s |= {sec.end for sec in self.img.sections if sec.holds_code}
        self.starts = sorted(s)
        self.sources: dict[str, list] = {}
        for f in st.facts(Kind.source):
            if f.run == "L.src" and f.value.get("what") == "func":
                self.sources.setdefault(f.value["unit"], []).append(f)
        self.byte = {}
        for a, u in byte_functions(p).items():
            self.byte.setdefault(u, set()).add(a)
        self.n = 0

    def matches(self, unit: str, texts: dict[str, str]) -> tuple[set | None, str]:
        """(the addresses of the unit that byte-match with these texts, '') or (None, the compiler's first error)."""
        import itertools
        from pathlib import Path as P
        a = self.amalgs[unit]
        text, _ = self.B.A.compose(self.p.root, a.members, a.file_name, read=texts.get)
        k = next(_counter)
        src = P("build") / "amalg" / "trial" / f"{unit}-{k}.c"
        obj = P("build") / "obj" / "trial" / f"{unit}-{k}.obj"
        (self.p.root / src).parent.mkdir(parents=True, exist_ok=True)
        (self.p.root / obj).parent.mkdir(parents=True, exist_ok=True)
        (self.p.root / src).write_text(text, newline="\n")
        flags, _ = self.B.flags_for(self.p, a.target, unit)
        res = self.tc.compile(src, obj, flags, self.B.include_dirs(unit), self.p.root)
        try:
            if not res.ok:
                err = next((d for d in res.diagnostics if d.severity == "error"), None)
                return None, (f"{err.file}({err.line}): {err.code} {err.message}" if err else "does not compile")
            o = self.p.objfmt.read_object(self.p.root / obj)
            index = self.C.function_index(o, self.tc)
            out = set()
            for s in self.sources.get(unit, []):
                sym = index.get(s.value["symbol"])
                if sym is None:
                    continue
                code = o.function_code(sym)
                i = bisect.bisect_right(self.starts, s.lo)
                nxt = self.starts[i] if i < len(self.starts) else self.img.end
                if self.C.compare(self.img, code, s.lo, self.relocs, nxt, self.tc.fill_forms).matched:
                    out.add(s.lo)
            return out, ""
        finally:
            for f in (src, obj):
                try:
                    (self.p.root / f).unlink()
                except OSError:
                    pass

    def judge(self, files: Files, unit: str, edits: list[Edit]) -> tuple[list[Edit], list[str]]:
        """(the accepted edits of the unit, why each rejected group fell)."""
        from concurrent.futures import ThreadPoolExecutor
        need = self.byte.get(unit, set())

        def verdict(es):
            got, err = self.matches(unit, apply(files, es))
            if got is None:
                return False, err
            lost = need - got
            return (not lost), (f"loses {len(lost)} byte match(es), first {min(lost):#x} (a definition here changes how "
                                f"this unit's code reaches it: the original may define it in another unit)" if lost else "")

        ok, why = verdict(edits)
        if ok:
            return edits, []
        groups: dict[str, list] = {}
        for e in edits:
            groups.setdefault(e.group or e.why, []).append(e)
        names = list(groups)
        with ThreadPoolExecutor(8) as pool:
            alone = dict(zip(names, pool.map(lambda g: verdict(groups[g]), names)))
        good = [g for g in names if alone[g][0]]
        rejected = [f"{g}: {alone[g][1]}" for g in names if not alone[g][0]]
        if good and verdict([e for g in good for e in groups[g]])[0]:
            return [e for g in good for e in groups[g]], rejected
        kept = []
        for g in good:                                    # the good groups interfere: add them one at a time
            if verdict([e for x in kept + [g] for e in groups[x]])[0]:
                kept.append(g)
            else:
                rejected.append(f"{g}: passes alone, not together with the others")
        return [e for g in kept for e in groups[g]], rejected


import itertools as _itertools
_counter = _itertools.count()
