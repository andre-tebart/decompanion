"""dcp: the drafting commands of the layout phase (milestone 4): unit new / join / rename, draft, rename. Same
output contract as cli.py: one record per line, key=value tokens, addresses 0x%08x, counts before lists.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cli import open_project, record, refresh
from .config import Project
from .ledger.fact import Kind


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


def rebuilt(args, p=None, e=None):
    """The project after an edit of the sources: the stale units compiled (when the toolchain is installed: the
    objects must define the new names, M.gen) and the rules refreshed. A project the command opened already is
    used again (its inputs are hashed afresh: refresh forgets src and decl)."""
    from .build import compile as B
    from .cli import build_target, lint_built
    if p is not None:
        if p.core.toolchain_available() and p.store.facts(Kind.build):
            B.ensure(p)
            lint_built(p)
        refresh(p, e)
        return p, e
    p, e = open_project(args)
    if p.core.toolchain_available() and p.store.facts(Kind.build):
        p, e, _ = build_target(args, getattr(args, "target", None), quiet=True)
    else:
        refresh(p, e)
    return p, e


# ------------------------------------------------------------------------------------------------ units
def cmd_unit_new(args):
    """`dcp layout unit propose` (L3 / L4 / L7 / L8 on the proposal, the boundary lines written to decl/text.dcl),
    then the unit's skeleton files: src/<unit>.c, include/<unit>.h, notes/units/<unit>.md (the ones missing)."""
    from . import native
    from .cli import cmd_layout_propose
    ns = argparse.Namespace(**{**vars(args), "dry_run": False})
    code = cmd_layout_propose(ns)
    if code:
        return code
    p = Project(Path(args.root) if getattr(args, "root", None) else None, getattr(args, "target", None))
    for line in native.core().unit_create(str(p.root), args.name, args.range, args.by, args.why):
        print(line)
    print("next: dcp draft --next  (the unit's functions in address order)")
    return 0


def report(cmd: str, res) -> int:
    lines, error, status = res
    if lines:
        print("\n".join(lines))
    return err(cmd, error) if error else status


def cmd_unit_join(args):
    """Join unit B into unit A (B directly follows A; the core's units.rs): B's head lines A lacks go into A's head
    region, B's functions follow A's in src/A.c, the headers and the notes merge, includes of B's header name A's,
    B's start boundary goes and its end becomes A's, the placeholders `B_<addr>` become `A_<addr>` (names.log). Both
    are built before and after: every function's code grade and the error count must stay as they were (a change is
    evidence to keep the units apart: revert with git); exit 1 otherwise."""
    from . import native
    from .cli import build_target
    p, e = open_project(args)
    refresh(p, e)
    return report("unit join", native.core().unit_join(p.core, args.a, args.b, args.why,
                                                        lambda: build_target(args, getattr(args, "target", None), quiet=True)))


def cmd_unit_rename(args):
    """Rename a unit (the core's units.rs): git mv of src/<old>.c, notes/units/<old>.md and include/<old>.h (its guard
    follows), every #include of the header, the boundary lines' tu= (and by= on the start line), the placeholders
    `<old>_<addr>` of its functions; names.log records each rename."""
    from . import native
    p, e = open_project(args)
    refresh(p, e)
    return report("unit rename", native.core().unit_rename(p.core, args.old, args.new, args.by, args.why, lambda: rebuilt(args)))


# ------------------------------------------------------------------------------------------------ draft
def cmd_draft(args):
    """Write the function at ADDR into its unit's file (the core's draft.rs): the address comment, the analyzer's
    pseudocode with the ledger's names (else a @rough skeleton with the disassembly), the declarations it needs.
    --next drafts the function `dcp layout next` shows. --show prints the analyzer's draft as it stored it and
    writes nothing."""
    from . import native
    from .rules.engine import capstone_dll
    p, e = open_project(args)
    refresh(p, e)
    return report("draft", native.core().draft_command(p.core, capstone_dll(), args.addr, bool(args.next), bool(args.show), args.unit,
                                                        p.analyzer_key))


# ------------------------------------------------------------------------------------------------ rename
def rename_fail(args, msg: str, old=None, new=None) -> int:
    """A refused or failed rename: the error record on stdout (key=value, like every result), the message on
    stderr; exit 1."""
    print(record(rename=old or args.old, to=new or args.new, error=msg))
    return err("rename", msg)


def cmd_rename(args):
    """Rename identifiers over src/, include/ and decl/ (the core's rename.rs: its module documentation states the
    rules); several OLD NEW pairs (and --from FILE) in one call, one rebuild for all of them."""
    from . import native
    from .config import ConfigError
    args.old, args.new = (args.pairs + ["", ""])[:2]
    error, pairs, tgt, first = native.core().rename_pairs(list(args.pairs), args.from_file, args.why)
    if error:
        return rename_fail(args, error)
    try:
        p, e = open_project(args, tgt or None) if tgt is not None else open_project(args)
    except ConfigError as ex:
        return rename_fail(args, f"{first}: {ex}", old=first, new=pairs[0][1])
    refresh(p, e)
    out, errs, status = native.core().rename_command(p.core, pairs, lambda: rebuilt(args, p, e))
    if out:
        print("\n".join(out))
    for m in errs:
        print(m, file=sys.stderr)
    return status
