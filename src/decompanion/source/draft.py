"""`dcp draft ADDR`: the first source fragment of a function, written from what the ledger knows.

The fragment src/<unit>/f_<addr>.c:
  line 1   the address comment `/* 0x10001234, <name> */` (`@rough` added when the body is a skeleton)
  body     Ghidra's pseudocode of the function when a draft exists (`dcp ghidra export` / `import`), its
           signature on one line, every name rewritten by the rules below; else an empty definition whose body
           is a comment holding the disassembly (the skeleton, `@rough`)
The name: the one the ledger registers for the address from a declaration, an export or the user entry
(ledger/names.py: decl, export, entry), else the placeholder `<unit>_<addr>` (8 hex digits; L5 checks that it
spells a start, Q1 that it gets replaced).

Names inside a Ghidra body:
  the function itself        its name above
  a function Ghidra names    (FUN_<hex>, thunk_FUN_<hex>, or a name Ghidra gave an address) the ledger's name for
                             the address (ledger/names.py: source, decl, export, entry, library, import), else the
                             placeholder `<unit>_<addr>` of the unit the address lies in, else `unk_<addr>`
  a data label of Ghidra's   (DAT_<hex>, _DAT_<hex>, PTR_..._<hex>, s_..._<hex>, u_..._<hex>, BYTE_ / WORD_ /
                             DWORD_ / QWORD_ / FLOAT_ / DOUBLE_..._<hex>) the ledger's name for the address when the
                             sources, a declaration or a library member name it, else `DAT_<hex>`
Every other spelling of the drafted function's address in src/ and include/ (a placeholder another draft wrote
before: `unk_10001234`, `FUN_10001234`, `other_10001234`) is renamed to its name at the same time, so one address
has one name in the sources.

Declarations (appended, never duplicated; source/edit.py), for every name the body uses that has an address:
  include/<unit>.h        the drafted function's prototype (the prototype lives in the defining unit's header);
                          `#include "dcp_ghidra.h"` when the prototype is Ghidra's (its type names)
  src/<unit>/head.c       `#include "dcp_ghidra.h"` (before the unit's header) for a Ghidra body, written to
                          include/ from the installation when missing; then per name:
    an import (a thunk or an import slot)   the system header that declares it (Toolchain.import_header)
    a C library function                    the system header that declares it (Toolchain.declaring_header)
    a name another unit's header declares   `#include "<that unit>.h"`
    any other function                      in head.c's dcp block: a K&R declaration with Ghidra's return type
                                            for a cdecl function, Ghidra's whole prototype for __stdcall /
                                            __fastcall (their decorated name needs the parameters), `int name();`
                                            without a Ghidra draft
    a datum                                 in head.c's dcp block: `extern <type> <name>;`, the type from the
                                            prefix of Ghidra's label (PTR_ `undefined *`, s_ / u_ `char <name>[]`,
                                            BYTE_ undefined1, WORD_ undefined2, QWORD_ undefined8, FLOAT_ float,
                                            DOUBLE_ double, else undefined4)
When a function is drafted, the declarations of its name in the dcp blocks are removed (its prototype is in its
unit's header now; a unit that calls it includes that header).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..ledger import srcscan
from . import edit as E

KEYWORDS = frozenset("""if while for switch return sizeof do else case default goto break continue typedef struct union enum
static extern const volatile register auto unsigned signed int char short long float double void __cdecl __stdcall
__fastcall __thiscall __int64 __declspec __asm""".split())
FUN = re.compile(r"\b(?:thunk_)?FUN_([0-9a-fA-F]{8})\b")
LABEL = re.compile(r"\b(_?DAT|PTR|s|u|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|UNK)_\w*?([0-9a-fA-F]{8})\b")
DATA_TYPES = {"PTR": "undefined *", "s": "char []", "u": "char []", "BYTE": "undefined1", "WORD": "undefined2",
              "QWORD": "undefined8", "FLOAT": "float", "DOUBLE": "double"}
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
CONV = re.compile(r"\b(__stdcall|__fastcall|__thiscall)\b")
DATA_HEADER = Path(__file__).resolve().parents[1] / "data" / "dcp_ghidra.h"
CANONICAL = ("decl", "export", "entry")
GHIDRA_INCLUDE = '#include "dcp_ghidra.h"'


class DraftError(RuntimeError):
    pass


@dataclass
class Draft:
    addr: int
    unit: str
    name: str
    file: str
    source: str                                       # ghidra | skeleton
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
    """(the signature on one line, the body from its opening brace on)."""
    head, sep, body = text.partition("{")
    return " ".join(head.split()), sep + body


def return_type(sig: str, name: str) -> str:
    """The return type of a signature (without the calling convention)."""
    before = sig.split(name + "(", 1)[0] if name + "(" in sig else sig.split("(", 1)[0].rsplit(" ", 1)[0]
    before = CONV.sub("", before).replace("__cdecl", "")
    return " ".join(before.split()) or "int"


def rewrite_ghidra(text: str, own: str, own_ghidra: str, names, view, ghidra_at: dict) -> tuple[str, dict]:
    """(the pseudocode with every name rewritten, {used name: (address, is a function)}) (module docstring)."""
    out = text
    if own_ghidra:
        out = re.sub(rf"\b{re.escape(own_ghidra)}\b", own, out)
    out = FUN.sub(lambda m: callee_name(names, view, int(m.group(1), 16)), out)
    named = {n: a for n, a in ghidra_at.items() if not FUN.fullmatch(n) and n != own_ghidra}
    if named:
        pat = re.compile(r"\b(" + "|".join(sorted(map(re.escape, named), key=len, reverse=True)) + r")\b")
        out = pat.sub(lambda m: callee_name(names, view, named[m.group(1)]), out)
    types = {}

    def label(m):
        a = int(m.group(2), 16)
        types.setdefault(a, DATA_TYPES.get(m.group(1), "undefined4"))
        return data_name(names, a)
    out = LABEL.sub(label, out)
    uses = {}
    _, body = split(out)
    code = E.TOKEN.sub(" ", body)
    for m in IDENT.finditer(code):
        n = m.group(0)
        if n in KEYWORDS or n == own or n in uses:
            continue
        hits = names.by_name.get(n)
        ph = srcscan.PLACEHOLDER_ADDR.fullmatch(n)
        a = sorted(hits)[0] if hits else (int(ph.group(1) or ph.group(2), 16) if ph else None)
        if a is None:
            continue
        uses[n] = (a, is_start(view, a), types.get(a, "undefined4"))
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
    return (f"void __cdecl {name}(void)\n{{\n    /* disassembly ({hi - a} bytes):\n" + "\n".join(body + more)
            + "\n     */\n}\n")


def ensure_ghidra_header(root: Path, head: Path, unit: str, d: "Draft"):
    dh = root / "include" / "dcp_ghidra.h"
    if not dh.exists():
        if not DATA_HEADER.exists():
            raise DraftError(f"{DATA_HEADER} is missing from the installation")
        E.write(dh, DATA_HEADER.read_text())
        d.declared.append("wrote include/dcp_ghidra.h (Ghidra's type names)")
    text = head.read_text()
    if GHIDRA_INCLUDE not in text:
        own = f'#include "{unit}.h"'
        lines = text.splitlines()
        at = next((i for i, l in enumerate(lines) if l.strip() == own), None)
        if at is None:
            E.ensure_include(head, GHIDRA_INCLUDE)
        else:
            lines.insert(at, GHIDRA_INCLUDE)
            E.write(head, "\n".join(lines) + "\n")
        d.declared.append(f"{head.relative_to(root).as_posix()}: {GHIDRA_INCLUDE}")


def draft(p, view, names, a: int, unit: str | None = None) -> Draft:
    """Write the fragment of the function at a (module docstring). DraftError when there is nothing to draft."""
    from ..ledger import ghidra as G
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
        raise DraftError(f"{rel} exists (it does not parse as a fragment: dcp conflicts)")
    d = Draft(a, tu, name, rel, "skeleton")
    entry = G.draft(p.store, p.image.sha256, a)
    ghidra_at = {e.name: e.start for e in G.entries(p.store) if e.name}
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
    if entry is not None and entry.text.strip():
        d.source = "ghidra"
        text, uses = rewrite_ghidra(entry.text, name, entry.name, names, view, ghidra_at)
        sig, body = split(text)
        d.uses = uses
        ensure_ghidra_header(root, head, tu, d)
        E.write(path, f"/* {a:#010x}, {name} */\n{sig}\n{body.strip(chr(10))}\n")
        if E.add_to_header(header, tu, sig + ";", name):
            d.declared.append(f"include/{tu}.h: {sig};")
        if E.ensure_after_guard(header, tu, GHIDRA_INCLUDE):
            d.declared.append(f"include/{tu}.h: {GHIDRA_INCLUDE}")
        declare_uses(p, names, view, head, tu, uses, ghidra_at, d)
    else:
        E.write(path, f"/* {a:#010x}, {name} @rough */\n" + skeleton(p, names, a, name))
        sig = f"void __cdecl {name}(void)"
        if E.add_to_header(header, tu, sig + ";", name):
            d.declared.append(f"include/{tu}.h: {sig};")
    return d


def header_declaring(root: Path, name: str, unit: str) -> str | None:
    """The unit header of include/ that declares `name` (its own unit's first)."""
    for h in sorted((root / "include").glob("*.h"), key=lambda h: (h.stem != unit, h.name)):
        if h.name != "dcp_ghidra.h" and E.declared_in(h.read_text(errors="replace"), name):
            return h.name
    return None


def declare_uses(p, names, view, head: Path, unit: str, uses: dict, ghidra_at: dict, d: Draft):
    """The includes and declarations the names of a draft need (module docstring)."""
    from ..ledger import ghidra as G
    root, tc = p.root, p.toolchain
    rel = head.relative_to(root).as_posix()
    entries = {e.start: e for e in G.entries(p.store)}

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
            if e is not None:
                sig, _ = split(rewrite_ghidra(e.text, n, e.name, names, view, ghidra_at)[0])
                decl = sig + ";" if CONV.search(sig) else f"{return_type(sig, n)} {n}();"
            else:
                decl = f"int {n}();"
        else:
            decl = f"extern char {n}[];" if dtype == "char []" else f"extern {dtype} {n};"
        if E.add_declaration(head, decl, n):
            d.declared.append(f"{rel}: {decl}")
