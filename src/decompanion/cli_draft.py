"""dcp: the drafting commands of the layout phase (milestone 4): unit new / join / rename, draft, rename. Same
output contract as cli.py: one record per line, key=value tokens, addresses 0x%08x, counts before lists.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cli import open_project, parse_addr, parse_range, record, refresh
from .config import Project
from .ledger.fact import Kind


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


def view_of(p, e):
    from .ledger import layoutview as LV
    refresh(p, e)
    return LV.View.load(p, p.store)


def rebuilt(args):
    """The project after an edit of the sources: the stale units compiled (when the toolchain is installed: the
    objects must define the new names, M.gen) and the rules refreshed."""
    from .cli import build_target
    p, e = open_project(args)
    if p.toolchain.available() and p.store.facts(Kind.build):
        p, e, _ = build_target(args, getattr(args, "target", None), quiet=True)
    else:
        refresh(p, e)
    return p, e


def errors(p) -> list:
    return [x for x in p.store.conflicts() if x.severity.value in ("bug", "error")]


# ------------------------------------------------------------------------------------------------ units
def cmd_unit_new(args):
    """`dcp layout unit propose` (L3 / L4 / L7 / L8 on the proposal, the boundary lines written to decl/text.dcl),
    then the unit's skeleton files: src/<unit>/head.c, include/<unit>.h, src/<unit>/open.md (the ones missing)."""
    from .cli import cmd_layout_propose
    from .source import units as U
    ns = argparse.Namespace(**{**vars(args), "dry_run": False})
    code = cmd_layout_propose(ns)
    if code:
        return code
    p = Project(Path(args.root) if getattr(args, "root", None) else None, getattr(args, "target", None))
    lo, hi = parse_range(args.range) if ".." in args.range else (parse_addr(args.range), None)
    for rel in U.create(p.root, args.name, lo, hi, args.by, args.why):
        print(f"wrote {rel}")
    print("next: dcp draft --next  (the unit's functions in address order)")
    return 0


def byte_state(p) -> tuple[dict, int]:
    """({function address: code grade} of the current grades, the number of bug / error conflicts)."""
    from .ledger import grades as G
    return {r["addr"]: r["code"] for r in G.function_grades(p.store)}, len(errors(p))


def cmd_unit_join(args):
    """Join unit B into unit A (B directly follows A): B's fragments move into src/A/ (git mv), head.c, tail.c, the
    headers and open.md merge, includes of B's header name A's, B's start boundary goes and its end becomes A's,
    the placeholders `B_<addr>` become `A_<addr>` (names.log). Both are built before and after: every function's
    code grade and the error count must stay as they were (a change is evidence to keep the units apart: revert
    with git); exit 1 otherwise."""
    from .cli import build_target
    from .source import edit as E
    from .source import units as U
    p, e = open_project(args)
    v = view_of(p, e)
    names = [u.tu for u in v.units]
    missing = next((u for u in (args.a, args.b) if u not in names), None)
    if missing:
        return err("unit join", f"no unit {missing} (units: {', '.join(names) or 'none'})")
    if names.index(args.b) != names.index(args.a) + 1:
        return err("unit join", f"{args.b} does not directly follow {args.a} (join neighbours, the earlier one first)")
    p, e, _ = build_target(args, getattr(args, "target", None), quiet=True)
    before, err_before = byte_state(p)
    try:
        j = U.join(p.root, [t.name for t in p.targets], args.a, args.b, args.why)
    except E.EditError as ex:
        return err("unit join", str(ex))
    events = [(int(o.rsplit("_", 1)[1], 16), "func", o, n) for o, n in sorted(j.renamed.items())]
    E.log_names(p.root, [(None, "unit", args.b, args.a)] + events, f"join: {args.why}")
    for m in j.moved:
        print("moved " + m)
    for c in j.decl:
        print("decl  " + c)
    for o, n in sorted(j.renamed.items()):
        print(f"renamed {o} -> {n}")
    p, e, _ = build_target(args, getattr(args, "target", None), quiet=True)
    after, err_after = byte_state(p)
    changed = sorted(a for a in set(before) | set(after) if before.get(a) != after.get(a))
    print(record(joined=args.b, into=args.a, byte_before=sum(1 for c in before.values() if c == "byte"),
                 byte_after=sum(1 for c in after.values() if c == "byte"), grades_changed=len(changed), errors_before=err_before,
                 errors_after=err_after))
    for a in changed:
        print("  " + record(fn=a, before=before.get(a), after=after.get(a)))
    if changed or err_after > err_before:
        print("the join changed grades or added errors: evidence to keep the units apart (revert: git checkout -- . && git clean -fd src include)")
        return 1
    return 0


def cmd_unit_rename(args):
    """Rename a unit: git mv of src/<old>/ (fragments, head.c, open.md) and include/<old>.h (its guard follows),
    every #include of the header, the boundary lines' tu= (and by= on the start line), the placeholders
    `<old>_<addr>` of its functions; names.log records each rename."""
    from .ledger import decl as D
    from .source import edit as E
    from .source import units as U
    p, e = open_project(args)
    v = view_of(p, e)
    if not D.UNIT.match(args.new) or not E.IDENT.match(E.c_name(args.new)):
        return err("unit rename", f"{args.new!r} is not a unit name")
    if args.old not in {u.tu for u in v.units} and not (p.root / "src" / args.old).exists():
        return err("unit rename", f"no unit {args.old}")
    try:
        r = U.rename(p.root, [t.name for t in p.targets], args.old, args.new, args.by)
    except E.EditError as ex:
        return err("unit rename", str(ex))
    events = [(int(o.rsplit("_", 1)[1], 16), "func", o, n) for o, n in sorted(r.renamed.items())]
    E.log_names(p.root, [(None, "unit", args.old, args.new)] + events, f"by={args.by or '-'}: {args.why}")
    for m in r.moved:
        print("moved " + m)
    for c in r.decl:
        print("decl  " + c)
    for o, n in sorted(r.renamed.items()):
        print(f"renamed {o} -> {n}")
    p, e = rebuilt(args)
    bad = errors(p)
    print(record(unit=args.old, renamed=args.new, by=args.by, includes=r.includes, placeholders=len(r.renamed), errors=len(bad)))
    return 1 if bad else 0


# ------------------------------------------------------------------------------------------------ draft
def show_draft(p, e, args):
    """The analyzer's draft of the function at (or around) ADDR, unchanged: a comment line, then its text."""
    from .cli import fmt_addr
    from .cli_read import resolve
    from .ledger import drafts as G
    from .ledger.names import Names
    refresh(p, e)
    if not args.addr:
        return err("draft", "--show needs ADDR")
    a = resolve(p, Names(p, p.store), args.addr)
    if a is None:
        return err("draft", f"{args.addr}: no such address or name")
    d = G.draft(p.store, p.image.sha256, a)
    if d is None:
        f = next((f for f in p.store.facts(Kind.symbol, a, a + 1) if f.value.get("skind") == "func"), None)
        if f is not None:
            d = G.draft(p.store, p.image.sha256, f.lo)
    if d is None:
        print(f"no draft at {fmt_addr(a)} (analyzer={p.analyzer.key}; dcp setup runs its export)")
        return 1
    print(f"/* {d.analyzer} draft of {fmt_addr(d.start)} {d.name} (requested {fmt_addr(d.requested)}, from {d.source}) */")
    sys.stdout.write(d.body)
    return 0


def cmd_draft(args):
    """Write the fragment of the function at ADDR (source/draft.py): the address comment, the analyzer's pseudocode
    with the ledger's names (else a @rough skeleton with the disassembly), the declarations it needs. --next drafts
    the function `dcp layout next` shows. --show prints the analyzer's draft as it stored it and writes nothing."""
    from .cli_read import resolve
    from .ledger import layoutview as LV
    from .ledger.names import Names
    from .source import draft as DR
    from .source import edit as E
    p, e = open_project(args)
    if args.show:
        return show_draft(p, e, args)
    v = view_of(p, e)
    names = Names(p, p.store)
    if args.next:
        recs = LV.next_records(v, 1)
        if not recs:
            print("nothing to draft: every function of the game code has a fragment")
            return 0
        r = recs[0]
        if r["kind"] == "unknown":
            return err("draft", f"the next open item {r['addr']:#x} is unknown code ({r['size']} bytes) no start explains: declare a "
                                f"start (`dcp decl add \"{r['addr']:#x} start -- why\"`) or dead bytes (`..END bytes dead -- why`)")
        a = r["addr"]
    else:
        if not args.addr:
            return err("draft", "ADDR or --next")
        a = resolve(p, names, args.addr)
        if a is None:
            return err("draft", f"{args.addr}: no such address or name")
    try:
        d = DR.draft(p, v, names, a, args.unit)
    except DR.DraftError as ex:
        return err("draft", str(ex))
    if d.renamed:
        E.log_names(p.root, [(a, "func", o, n) for o, n in sorted(d.renamed.items())], f"drafted at {a:#010x}")
    fn = next((f for lo, hi, f in v.funcs if lo == a), None)
    print(record(drafted=a, name=d.name, unit=d.unit, file=d.file, body=d.source, size=(fn.hi - fn.lo) if fn else None,
                 uses=len(d.uses)))
    for o, n in sorted(d.renamed.items()):
        print(f"  renamed {o} -> {n}")
    for x in d.declared:
        print("  " + x)
    print(f"next: dcp build, dcp grade {d.unit}")
    return 0


# ------------------------------------------------------------------------------------------------ rename
def cmd_rename(args):
    """Rename one identifier: every whole-word occurrence in src/ and include/ (comments and strings too), an
    unlinked fragment's file u_<old>.c, the `name` declarations of decl/*.dcl; refused when OLD occurs nowhere, or
    when NEW occurs already and is not OLD's own (the ledger names another address NEW, or OLD has no address):
    NEW written by hand in part for OLD's address is completed. names.log records the event, with the address the ledger knows for OLD
    (a name fact, or the address a placeholder spells). The rename done by hand already (OLD nowhere, NEW the
    ledger's name of OLD's address) is only recorded: names.log gets the event, no file changes."""
    from .ledger import srcscan
    from .ledger.names import Names
    from .source import edit as E
    p, e = open_project(args)
    refresh(p, e)
    if not E.IDENT.match(args.new) or not E.IDENT.match(args.old):
        return err("rename", "OLD and NEW are C identifiers")
    names = Names(p, p.store)
    hits = names.by_name.get(args.old)
    ph = srcscan.PLACEHOLDER_ADDR.fullmatch(args.old)
    a = sorted(hits)[0] if hits else (int(ph.group(1) or ph.group(2), 16) if ph else None)
    kind = "ident"
    if a is not None:
        sym = names.symbol(a)
        sk = sym.value.get("skind") if sym is not None else None
        starts = {f.lo for f in p.store.facts(Kind.start, a, a + 1)}
        kind = "func" if sk in ("func", "thunk") and (sym.lo == a or a in starts) else "data"
    if not E.uses(p.root, args.old):
        if a is not None and a in names.by_name.get(args.new, ()):
            E.log_names(p.root, [(a, kind, args.old, args.new)], args.why)
            print(record(recorded=args.old, to=args.new, kind=kind, at=a, files=0) + "  (renamed by hand already: names.log only)")
            return 0
        return err("rename", f"{args.old} occurs nowhere in src/ or include/" + (
            f" and {args.new} is not the ledger's name of {a:#x}" if a is not None else ""))
    clash = E.code_uses(p.root, args.new)
    elsewhere = sorted(set(names.by_name.get(args.new, ())) - ({a} if a is not None else set()))
    if clash and (a is None or elsewhere):
        return err("rename", f"{args.new} exists already ({clash[0][0]}:{clash[0][1]})"
                             + (f", the ledger's name at {', '.join(f'{x:#x}' for x in elsewhere)}" if elsewhere else "")
                             + ": refused (a collision)")
    if clash:                                       # NEW is OLD's own address's name, written by hand in part
        print(f"note: {args.new} occurs already ({clash[0][0]}:{clash[0][1]}) and names no other address: the rename "
              f"completes it")
    n = E.rename_words(p.root, {args.old: args.new})
    for f in sorted((p.root / "src").glob(f"*/u_{args.old}.c")):
        E.move(p.root, f, f.with_name(f"u_{args.new}.c"))
        print(f"moved {f.relative_to(p.root).as_posix()} -> u_{args.new}.c")
    for path in sorted((p.root / "decl").glob("*.dcl")):
        t = path.read_text()
        new = "\n".join((l.replace(f" name {args.old} ", f" name {args.new} ") if " name " in l else l) for l in t.splitlines()) + "\n"
        if new != t:
            E.write(path, new)
            print(f"decl  {path.relative_to(p.root).as_posix()}: name {args.old} -> {args.new}")
    E.log_names(p.root, [(a, kind, args.old, args.new)], args.why)
    print(record(renamed=args.old, to=args.new, kind=kind, at=a, files=len(n), replacements=sum(n.values())))
    p, e = rebuilt(args)
    bad = errors(p)
    if bad:
        print(f"check: {len(bad)} error(s) after the rename (dcp check lists them)")
    return 1 if bad else 0
