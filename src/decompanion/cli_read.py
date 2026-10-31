"""dcp: the reading commands of the layout phase (milestone 4): disasm, dump, refs, layout literals, layout fptrs,
layout starts. Same output contract as cli.py: one record per line, key=value tokens, addresses 0x%08x, counts
before lists. The core reads (cliread.rs); this module prints what it returns.
"""
from __future__ import annotations

import sys

from . import native
from .cli import open_project, refresh


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


def resolve(p, key: str) -> int | None:
    """An address from `0xADDR`, a name the ledger knows, or a placeholder spelling one."""
    return native.core().read_resolve(p.core, key)


def read(p, cmd: str, **args) -> tuple[list[str], str | None]:
    from .rules.engine import capstone_dll
    vals = {k: (None if v is None or v is False else "1" if v is True else str(v)) for k, v in args.items()}
    return native.core().read_command(p.core, capstone_dll(), cmd, vals)


def run(args, title: str, cmd: str, **kw) -> int:
    p, e = open_project(args)
    refresh(p, e)
    lines, error = read(p, cmd, **kw)
    if lines:
        print("\n".join(lines))
    return err(title, error) if error else 0


def cmd_disasm(args):
    """The original's instructions at ADDR (through the target's ISA plugin) with the ledger's name after every
    address operand. Default length: the rest of the function holding ADDR (else up to the next start, at most
    0x400 bytes); LEN as a byte count or `..END`. --ours NAME: our compiled function from its unit's object,
    each relocated field with the symbol our object refers to."""
    if args.ours:
        return run(args, "disasm", "disasm-ours", name=args.ours)
    return run(args, "disasm", "disasm", addr=args.addr, len=args.len)


def cmd_dump(args):
    """The original's bytes at ADDR: 16 per row as hex and latin-1, with the symbols that start in each row;
    clipped at the end of the section, rows beyond its file data marked. --str: every NUL-terminated string
    starting in the range; --dword: every aligned dword as unsigned, signed and float, with its name when it is
    an address; --float: every aligned float, and the double at every 8-aligned offset."""
    return run(args, "dump", "dump", addr=args.addr, len=args.len, str=args.str, dword=args.dword, float=args.float)


def cmd_refs(args):
    """Everything that names one function or datum: its definition and address comment, every fact that names
    the address (name facts of every origin, declarations, the analyzer's draft), the symbol and unit there, every
    reference to it and from it (with the ledger's names), and every line of src/ and include/ that mentions
    one of its names as a whole word or its address as a number."""
    return run(args, "refs", "refs", what=args.what)


def cmd_layout_literals(args):
    """The literal-pool view of a unit or a range (B-LIT made visible): every data address the functions of the
    range refer to, in address order per section, with its first user (the lowest function start among all its
    users in the image) and that user's unit; the block of each function (the lowest and highest literal it is
    the first user of, and the jump from the highest literal first used by an earlier function: a big forward
    jump skips another unit's block, and `between=` names the later functions (and their units) whose literals
    fill the gap: the objects the link order puts in between); per unit the block of its first-used pooled literals (strings and
    constants of read-only sections, reached from code only) and whether it interleaves with a neighbour's.
    VC6 /GF + LINK: pooled literals sit with their first user in link order, so neighbouring units' blocks do
    not interleave."""
    return run(args, "layout literals", "literals", what=args.what)


def cmd_layout_fptrs(args):
    """Every function pointer in data: a relocated address field (a `ref` reloc fact) outside the code sections
    whose target is a known function start, in site order, with the function's name and unit and the distance
    to the previous site of the same section (`delta=`: a repeating delta is the stride of a table of structs,
    such as zlib's configuration_table). A unit or a code range selects by the functions pointed to, a data
    range by the sites; default: every function pointer."""
    return run(args, "layout fptrs", "fptrs", what=args.what)


def cmd_layout_starts(args):
    """Every function start in a range (default: the game code) with its evidence: every `how` of its start
    facts (export, entry, crt, libref, call, tail, immediate, fptr, decl, source, the analyzer's key), the number of code
    sites that reach it (call, tail, immediate, relocation, operand), the size to the next start, the walk's
    extent, what precedes it (B-FILL), its unit, whether a source drafts it and whether the analyzer has a draft."""
    return run(args, "layout starts", "starts", range="..".join(args.range) if args.range else None)
