"""`dcp draft ADDR`: the first source fragment of a function, written from what the ledger knows.

The fragment src/<unit>/f_<addr>.c:
  line 1   the address comment `/* 0x10001234, <name> */` (`@rough` added when the body is a skeleton)
  body     the analyzer's pseudocode of the function when it has a draft (ledger/drafts.py, `dcp setup` runs
           the export), its signature on one line, every name rewritten by the rules below; else an empty
           definition whose body is a comment holding the disassembly (the skeleton, `@rough`)
The name: the one the ledger registers for the address from a declaration, an export or the user entry
(ledger/names.py: decl, export, entry), else the placeholder `<unit>_<addr>` (8 hex digits; L5 checks that it
spells a start, Q1 that it gets replaced).

Two dialects meet here: the analyzer's in (Analyzer.rewrite / data_labels / types_header, analyzers/), the
toolchain's language out (Toolchain.keywords / default_convention / sized_conventions, declaring_header,
import_header). This module knows C only.

Names inside an analyzer's body (Analyzer.rewrite):
  the function itself        its name above
  a function it names        (Ghidra: FUN_<hex>, thunk_FUN_<hex>, or a name it gave an address) the ledger's name
                             for the address (ledger/names.py: source, decl, export, entry, library, import), else
                             the placeholder `<unit>_<addr>` of the unit the address lies in, else `unk_<addr>`
  a data label of its own    (Ghidra: DAT_<hex>, PTR_..._<hex>, s_..._<hex>, ...) the ledger's name for the address
                             when the sources, a declaration or a library member name it, else `DAT_<hex>`
Every other spelling of the drafted function's address in src/ and include/ (a placeholder another draft wrote
before: `unk_10001234`, `FUN_10001234`, `other_10001234`) is renamed to its name at the same time, so one address
has one name in the sources.

Declarations (appended, never duplicated; source/edit.py), for every name the body uses that has an address:
  include/<unit>.h        the drafted function's prototype (the prototype lives in the defining unit's header);
                          `#include "<types header>"` when the prototype is the analyzer's (its type names)
  src/<unit>/head.c       `#include "<types header>"` (before the unit's header) for an analyzer's body, written
                          to include/ from the installation when missing; then per name:
    an import (a thunk or an import slot)   the system header that declares it (Toolchain.import_header)
    a C library function                    the system header that declares it (Toolchain.declaring_header)
    a name another unit's header declares   `#include "<that unit>.h"`
    any other function                      in head.c's dcp block: a K&R declaration with the analyzer's return
                                            type, its whole prototype for a convention whose decorated name
                                            needs the parameters (Toolchain.sized_conventions: VC6 __stdcall /
                                            __fastcall), `int name();` without a draft
    a datum                                 in head.c's dcp block: `extern <type> <name>;`, the type from the
                                            spelling of the analyzer's label (Analyzer.data_labels; Ghidra: PTR_
                                            `undefined *`, s_ / u_ `char <name>[]`, ...), else its
                                            unknown_data_type
When a function is drafted, the declarations of its name in the dcp blocks are removed (its prototype is in its
unit's header now; a unit that calls it includes that header).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import analyzers, fsmemo
from ..analyzers.base import Names as Spelling
from ..ledger import srcscan
from . import edit as E

C_KEYWORDS = frozenset("""if while for switch return sizeof do else case default goto break continue typedef struct union enum
static extern const volatile register auto unsigned signed int char short long float double void""".split())
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
COMMENT = re.compile(r"/\*.*?\*/", re.S)
CANONICAL = ("decl", "export", "entry")


class DraftError(RuntimeError):
    pass


@dataclass
class Draft:
    addr: int
    unit: str
    name: str
    file: str
    source: str                                       # the analyzer's key | skeleton
    renamed: dict = field(default_factory=dict)       # old placeholder -> name (project-wide)
    declared: list = field(default_factory=list)      # what was added to head.c / the header
    uses: dict = field(default_factory=dict)          # name -> (address, function?)


def placeholder(unit: str, a: int) -> str:
    return f"{E.c_name(unit)}_{a:08x}"


def function_name(names, unit: str, a: int) -> str:
    """The name a new fragment defines (module docstring)."""
    n, origin = names.at.get(a, (None, None))
    if n and origin in CANONICAL:
        return n
    return placeholder(unit, a)


def is_start(view, a: int) -> bool:
    return a in view.starts or any(lo == a for lo, _, _ in view.funcs) or (view.symbol_kind(a) == "thunk")


def callee_name(names, view, a: int) -> str:
    """How a draft spells a function at a: the ledger's name, else the placeholder of its unit, else unk_<addr>."""
    n = names.name(a)
    if n:
        return n
    u = view.unit_at(a)
    return placeholder(u.tu, a) if u is not None else f"unk_{a:08x}"


def data_name(names, a: int) -> str:
    n = names.name(a)
    return n if n and names.origin(a) in ("source", "decl", "lib") else f"DAT_{a:08x}"


def split(text: str) -> tuple[str, str]:
    """(the signature on one line without the analyzer's comments before it, the body from its opening brace
    on)."""
    head, sep, body = text.partition("{")
    return " ".join(COMMENT.sub(" ", head).split()), sep + body


def lead_comments(text: str) -> list[str]:
    """The analyzer's comments before the signature (Ghidra's `/* WARNING: ... */`), each for a line of its own:
    a comment on the signature's line hides the definition from the fragment scan."""
    return [" ".join(c.split()) for c in COMMENT.findall(text.partition("{")[0])]


def conventions(tc) -> re.Pattern | None:
    """A pattern of the toolchain's calling conventions whose decorated name needs the parameters."""
    return re.compile(r"\b(" + "|".join(map(re.escape, tc.sized_conventions)) + r")\b") if tc.sized_conventions else None


def return_type(tc, sig: str, name: str) -> str:
    """The return type of a signature (without the calling convention)."""
    before = sig.split(name + "(", 1)[0] if name + "(" in sig else sig.split("(", 1)[0].rsplit(" ", 1)[0]
    for conv in (tc.default_convention, *tc.sized_conventions):
        if conv:
            before = re.sub(rf"\b{re.escape(conv)}\b", "", before)
    return " ".join(before.split()) or "int"


def skeleton_signature(tc, name: str) -> str:
    conv = f"{tc.default_convention} " if tc.default_convention else ""
    return f"void {conv}{name}(void)"


def rewrite_body(p, entry, own: str, names, view, labels: dict) -> tuple[str, dict]:
    """(an analyzer's pseudocode with every name rewritten, {used name: (address, is a function, data type)})
    (module docstring)."""
    az = analyzers.dialect(entry.analyzer)
    types = az.data_labels(entry.body)
    out = az.rewrite(entry.body, (entry.name, own),
                     Spelling(lambda a: callee_name(names, view, a), lambda a: data_name(names, a)), labels)
    keywords = C_KEYWORDS | p.toolchain.keywords
    uses = {}
    _, body = split(out)
    code = E.TOKEN.sub(" ", body)
    for m in IDENT.finditer(code):
        n = m.group(0)
        if n in keywords or n == own or n in uses:
            continue
        hits = names.by_name.get(n)
        ph = srcscan.PLACEHOLDER_ADDR.fullmatch(n)
        a = sorted(hits)[0] if hits else (srcscan.placeholder_value(ph) if ph else None)
        if a is None:
            continue
        uses[n] = (a, is_start(view, a), types.get(a, az.unknown_data_type))
    return out, uses


def skeleton(p, names, a: int, name: str) -> str:
    """An empty definition whose body comment holds the disassembly of the walk's extent (at most 0x400 bytes)."""
    from ..cli_read import annotate, walk_func
    img, isa = p.image, p.isa
    fn = walk_func(p, a)
    hi = min(fn.hi if fn is not None else a + 0x40, a + 0x400)
    lines = isa.disasm(img.read(a, hi - a), a, p.toolchain.fill_forms)
    body = [f"       {ln.addr:#010x}  {annotate(isa, names, ln.text)}".replace("*/", "* /") for ln in lines]
    more = [f"       ... {fn.hi - hi} more bytes: dcp disasm {a:#x}"] if fn is not None and fn.hi > hi else []
    return (f"{skeleton_signature(p.toolchain, name)}\n{{\n    /* disassembly ({hi - a} bytes):\n" + "\n".join(body + more)
            + "\n     */\n}\n")


def types_headers() -> set[str]:
    """The file names of every analyzer's types header (no unit header)."""
    return {cls.types_header.name for cls in analyzers.ANALYZERS.values() if cls.types_header is not None}


def ensure_types_header(root: Path, head: Path, unit: str, shipped: Path, d: "Draft") -> str:
    """include/<the analyzer's types header> (copied from the installation, again when the installation's copy
    differs: the file is dcp's, not the project's) and its #include in head.c before the unit's own header;
    returns the #include line."""
    line = f'#include "{shipped.name}"'
    dh = root / "include" / shipped.name
    if not shipped.exists():
        raise DraftError(f"{shipped} is missing from the installation")
    want = shipped.read_text()
    if not dh.exists() or dh.read_text() != want:
        d.declared.append(f"{'updated' if dh.exists() else 'wrote'} include/{shipped.name} (the analyzer's type names)")
        E.write(dh, want)
    text = head.read_text()
    if line not in text:
        own = f'#include "{unit}.h"'
        lines = text.splitlines()
        at = next((i for i, l in enumerate(lines) if l.strip() == own), None)
        if at is None:
            E.ensure_include(head, line)
        else:
            lines.insert(at, line)
            E.write(head, "\n".join(lines) + "\n")
        d.declared.append(f"{head.relative_to(root).as_posix()}: {line}")
    return line


def draft(p, view, names, a: int, unit: str | None = None) -> Draft:
    """Write the fragment of the function at a (module docstring). DraftError when there is nothing to draft."""
    from ..ledger import drafts as G
    root = p.root
    u = view.unit_at(a)
    if unit is not None and u is not None and u.tu != unit:
        raise DraftError(f"{a:#x} lies in unit {u.tu} ({u.lo:#x}..{u.hi:#x}), not in {unit}")
    if u is None and unit is None:
        raise DraftError(f"{a:#x} lies in no unit: declare one first (dcp unit new NAME --range LO..HI --by ... --why ...)")
    tu = u.tu if u is not None else unit
    if a in view.sources:
        raise DraftError(f"{a:#x} is drafted already: {view.sources[a].value['file']}")
    if not (a in view.starts or any(lo == a for lo, _, _ in view.funcs)):
        raise DraftError(f"no function starts at {a:#x} (dcp layout starts; declare one with `ADDR start -- why`)")
    name = function_name(names, tu, a)
    rel = f"src/{tu}/f_{a:08x}.c"
    path = root / rel
    if path.exists():
        why = [f"{e.file}:{e.line}: {e.check} {e.message}" for e in srcscan.scan(root).errors if e.file == rel]
        raise DraftError(f"{rel} exists but does not parse as a fragment: " + ("; ".join(why) or "dcp conflicts"))
    d = Draft(a, tu, name, rel, "skeleton")
    entry = G.draft(p.store, p.image.sha256, a)
    all_entries = G.entries(p.store)
    labels = {e.name: e.start for e in all_entries if e.name}
    head = root / "src" / tu / "head.c"
    header = root / "include" / f"{tu}.h"
    if not head.exists():
        E.write(head, f"/* {tu}: the unit's includes, local types and declarations */\n#include \"{tu}.h\"\n")
    if not header.exists():
        E.write(header, E.header_text(tu, ""))
    E.ensure_include(head, f'#include "{tu}.h"')
    # one address, one name: earlier placeholders of this address follow
    olds = sorted({ph.ident for ph in srcscan.scan(root).placeholders if ph.value == a and ph.ident != name})
    if olds:
        d.renamed = {o: name for o in olds}
        E.rename_words(root, d.renamed)
    for f in (root / "src").glob("*/head.c"):
        if E.drop_declarations(f, name):
            d.declared.append(f"dropped the declaration of {name} from {f.relative_to(root).as_posix()}'s dcp block")
    if entry is not None and entry.body.strip():
        d.source = entry.analyzer
        text, uses = rewrite_body(p, entry, name, names, view, labels)
        sig, body = split(text)
        d.uses = uses
        shipped = analyzers.dialect(entry.analyzer).types_header
        include = ensure_types_header(root, head, tu, shipped, d) if shipped is not None else None
        lead = "".join(c + "\n" for c in lead_comments(text))
        E.write(path, f"/* {a:#010x}, {name} */\n{lead}{sig}\n{body.strip(chr(10))}\n")
        if E.add_to_header(header, tu, sig + ";", name):
            d.declared.append(f"include/{tu}.h: {sig};")
        if include is not None and E.ensure_after_guard(header, tu, include):
            d.declared.append(f"include/{tu}.h: {include}")
        declare_uses(p, names, view, head, tu, uses, {e.start: e for e in all_entries}, labels, d)
    else:
        sig = skeleton_signature(p.toolchain, name)
        E.write(path, f"/* {a:#010x}, {name} @rough */\n" + skeleton(p, names, a, name))
        if E.add_to_header(header, tu, sig + ";", name):
            d.declared.append(f"include/{tu}.h: {sig};")
    return d


def header_declaring(root: Path, name: str, unit: str) -> str | None:
    """The unit header of include/ that declares `name` (its own unit's first): a function or data declaration of
    the front end's model of the header (srcscan.model_of)."""
    skip = types_headers()
    for h in sorted((root / "include").glob("*.h"), key=lambda h: (h.stem != unit, h.name)):
        if h.name in skip:
            continue
        m = srcscan.model_of(root, f"include/{h.name}", fsmemo.read_text(h)) or srcscan.EMPTY
        if any(d[1] == name for d in m["decls"]):
            return h.name
    return None


def declare_uses(p, names, view, head: Path, unit: str, uses: dict, entries: dict, labels: dict, d: Draft):
    """The includes and declarations the names of a draft need (module docstring)."""
    root, tc = p.root, p.toolchain
    rel = head.relative_to(root).as_posix()
    sized = conventions(tc)

    def include(line):
        if E.ensure_include(head, line):
            d.declared.append(f"{rel}: {line}")

    for n, (a, func, dtype) in sorted(uses.items()):
        imported = names.origin(a) == "import" or view.symbol_kind(a) in ("thunk", "iat")
        if imported:
            h = tc.import_header("")
            if h:
                include(f"#include <{h}>")
            continue
        h = tc.declaring_header(n) if func else None
        if h:
            include(f"#include <{h}>")
            continue
        hdr = header_declaring(root, n, unit)
        if hdr:
            if hdr != f"{unit}.h":
                include(f'#include "{hdr}"')
            continue
        if func:
            e = entries.get(a)
            if e is not None and e.body.strip():
                sig, _ = split(rewrite_body(p, e, n, names, view, labels)[0])
                decl = sig + ";" if sized is not None and sized.search(sig) else f"{return_type(tc, sig, n)} {n}();"
            else:
                decl = f"int {n}();"
        else:
            decl = f"extern char {n}[];" if dtype == "char []" else f"extern {dtype} {n};"
        if E.add_declaration(head, decl, n):
            d.declared.append(f"{rel}: {decl}")
