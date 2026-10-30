"""dcp: the drafting commands of the layout phase (milestone 4): unit new / join / rename, draft, rename. Same
output contract as cli.py: one record per line, key=value tokens, addresses 0x%08x, counts before lists.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import timing
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


def rebuilt(args, p=None, e=None):
    """The project after an edit of the sources: the stale units compiled (when the toolchain is installed: the
    objects must define the new names, M.gen) and the rules refreshed. A project the command opened already is
    used again (its inputs are hashed afresh: refresh forgets src and decl)."""
    from .build import compile as B
    from .cli import build_target, lint_built
    if p is not None:
        if p.toolchain.available() and p.store.facts(Kind.build):
            B.ensure(p)
            lint_built(p)
        refresh(p, e)
        return p, e
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
    then the unit's skeleton files: src/<unit>.c, include/<unit>.h, notes/units/<unit>.md (the ones missing)."""
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
    """Join unit B into unit A (B directly follows A): B's head lines A lacks go into A's head region, B's
    functions follow A's in src/A.c, the headers and the notes merge, includes of B's header name A's, B's start boundary goes and its end becomes A's,
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
    """Rename a unit: git mv of src/<old>.c, notes/units/<old>.md and include/<old>.h (its guard follows),
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
    """Write the function at ADDR into its unit's file (source/draft.py): the address comment, the analyzer's pseudocode
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
            print("nothing to draft: every function of the game code has a source")
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
DECL_NAME = r"(?m)(?<= name ){old}(?= |$)"


def rename_fail(args, msg: str, old=None, new=None) -> int:
    """A refused or failed rename: the error record on stdout (key=value, like every result), the message on
    stderr; exit 1."""
    print(record(rename=old or args.old, to=new or args.new, error=msg))
    return err("rename", msg)


def rename_pairs(args) -> list[tuple[str, str, str]] | str:
    """The (OLD, NEW, why) of a rename call: the OLD NEW pairs of the command line with --why, then the lines of
    --from FILE (`OLD NEW [why]`, a line without a why takes --why; blank lines and `#` lines skipped). A
    message instead when the call is malformed."""
    words = list(args.pairs)
    if len(words) % 2:
        return f"OLD NEW pairs expected, got {len(words)} word(s): {' '.join(words)}"
    pairs = [(words[i], words[i + 1], args.why) for i in range(0, len(words), 2)]
    if args.from_file:
        try:
            text = Path(args.from_file).read_text()
        except OSError as ex:
            return f"--from {args.from_file}: {ex}"
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            f = line.split(None, 2)
            if len(f) < 2:
                return f"--from {args.from_file}:{n}: `OLD NEW [why]` expected"
            why = f[2].strip() if len(f) > 2 else args.why
            if not why:
                return f"--from {args.from_file}:{n}: no why (give one on the line or --why)"
            pairs.append((f[0], f[1], why))
    if not pairs:
        return "nothing to rename: give OLD NEW (or --from FILE)"
    if any(w is None for _, _, w in pairs):
        return "--why is required (or a why on each --from line)"
    return pairs


class RenamePlan:
    """One pair of a rename call, checked and not yet written: what cmd_rename applies."""

    def __init__(self, old_arg, old, new, why, a, kind, exact, decls, recorded=False):
        self.old_arg, self.old, self.new, self.why, self.a, self.kind = old_arg, old, new, why, a, kind
        self.exact, self.decls, self.recorded = exact, decls, recorded
        self.used = []


def cmd_rename(args):
    """Rename identifiers: every whole-word occurrence in src/ and include/ (code and comments; string
    literals and #include lines are left alone), the `name` declarations of decl/*.dcl. Several OLD NEW pairs
    (and --from FILE) are renamed in one call: one refresh, one rebuild, one check for all of them, and nothing
    is written unless every pair passes (a refusal record per failing pair). OLD is a C identifier or an
    address (`0xADDR`, `TARGET:0xADDR`): the ledger's name of the address on that target (every pair of a call
    on one target). Refused (an error record, exit 1, nothing written) when OLD names nothing renamable: no such
    address name, OLD occurs nowhere, or only inside string literals / #include lines; when NEW is no C
    identifier or equals OLD; when NEW occurs already and is not OLD's own (the ledger names another address
    NEW, or OLD has no address): NEW written by hand in part for OLD's address is completed; when the pairs of
    a call chain or repeat (an OLD or a NEW twice, a NEW that is another pair's OLD). A success prints per pair
    the rename record (files, replacements, decl lines) and one line per changed file with its replacements.
    names.log records each event, with the address the ledger knows for OLD (a name fact, or the address a
    placeholder spells). The rename done by hand already (OLD nowhere, NEW the ledger's name of OLD's address)
    is only recorded: names.log gets the event, no file changes. The views of OLD (OLD with an upper-case view
    suffix, srcscan.PLACEHOLDER_ADDR) keep their names: a note lists them."""
    from .config import ConfigError
    from .ledger import srcscan
    from .ledger.names import Names
    from .source import edit as E
    args.old, args.new = (args.pairs + ["", ""])[:2]
    pairs = rename_pairs(args)
    if isinstance(pairs, str):
        return rename_fail(args, pairs)
    tgts = {o.strip().rpartition(":")[0] for o, _, _ in pairs if o.strip().rpartition(":")[2].lower().startswith("0x")}
    if len(tgts) > 1:
        return rename_fail(args, f"the pairs name several targets ({', '.join(sorted(t or '(default)' for t in tgts))}): one call "
                                 f"renames on one target")
    tgt = next(iter(tgts), "")
    try:
        p, e = open_project(args, tgt or None) if tgts else open_project(args)
    except ConfigError as ex:
        bad = next(o for o, _, _ in pairs if o.strip().rpartition(":")[2].lower().startswith("0x"))
        return rename_fail(args, f"{bad.strip()}: {ex}", old=bad.strip(), new=pairs[0][1])
    refresh(p, e)
    names = Names(p, p.store)
    before = {(x.check, x.lo, x.message) for x in errors(p)}
    plans, refusals = [], []
    words = [o.strip() for o, _, _ in pairs]
    for old_arg, new, why in pairs:
        if new in words and new != old_arg.strip():   # the later pair's OLD exists only after the earlier one is written
            refusals.append((old_arg.strip(), new, f"{new} is another pair's OLD: a chain (rename in two calls)"))
            continue
        with timing.phase("rename.plan"):
            r = plan_rename(p, names, old_arg.strip(), new, why)
        (refusals if isinstance(r, tuple) else plans).append(r)
    olds, news = [x.old for x in plans], [x.new for x in plans]
    for x in plans:
        if olds.count(x.old) > 1:
            refusals.append((x.old, x.new, f"{x.old} is renamed by several pairs of the call"))
        elif news.count(x.new) > 1:
            refusals.append((x.old, x.new, f"{x.new} is the new name of several pairs of the call"))
        elif x.new in olds:
            refusals.append((x.old, x.new, f"{x.new} is another pair's OLD: a chain (rename in two calls)"))
    if not refusals:
        with timing.phase("rename.check"):
            refusals = check_renames(p, names, [x for x in plans if not x.recorded])
    if refusals:
        for old, new, msg in refusals:
            rename_fail(args, msg, old=old, new=new)
        if len(pairs) > 1:
            print(f"rename: {len(refusals)} of {len(pairs)} pair(s) refused: nothing written")
        return 1
    for x in plans:
        if x.recorded:
            E.log_names(p.root, [(x.a, x.kind, x.old, x.new)], x.why)
            print(record(recorded=x.old, to=x.new, kind=x.kind, at=x.a, files=0) + "  (renamed by hand already: names.log only)")
    edits = [x for x in plans if not x.recorded]
    if not edits:
        return 0
    with timing.phase("rename.write"):
        write_renames(p, edits)
    for x in edits:
        E.log_names(p.root, [(x.a, x.kind, x.old, x.new)], x.why)
        print(record(renamed=x.old, to=x.new, kind=x.kind, at=x.a, files=len(x.files), replacements=sum(x.files.values()),
                     decl=x.decl_lines))
        for f, k in sorted(x.files.items()):
            print("  " + record(file=f, replacements=k))
        ph = srcscan.PLACEHOLDER_ADDR.fullmatch(x.old)
        views = sorted(w for w in E.words_with_prefix(p.root, x.old) if w != x.old and w[len(x.old)].isupper() and ph
                       and (m := srcscan.PLACEHOLDER_ADDR.fullmatch(w)) and srcscan.placeholder_value(m) == x.a)
        if views:
            print(f"note: the views of {x.old} keep their names: {', '.join(views[:8])} (rename each: dcp rename VIEW NEW)")
    p, e = rebuilt(args, p, e)
    bad = errors(p)
    new = [x for x in bad if (x.check, x.lo, x.message) not in before]
    if bad:
        print(f"check: {len(new)} new error(s) after the rename, {len(bad) - len(new)} from before (dcp check lists them)")
    for x in new[:10]:
        print(f"  {x.severity.value} {x.check} {x.lo:#010x}: {x.message}")
    return 1 if new else 0


def plan_rename(p, names, old_arg: str, new: str, why: str):
    """One pair checked against the tree as it stands (nothing written): a RenamePlan, or (old, new, message) when
    the pair is refused. The collisions of NEW and the symbol-exact occurrences are checked for all pairs at once
    (check_renames)."""
    import re
    from .ledger import srcscan
    from .source import edit as E
    tgt, _, addr = old_arg.rpartition(":")
    given = None
    if not E.IDENT.match(new):
        return old_arg, new, f"NEW {new!r} is no C identifier"
    if addr.lower().startswith("0x"):
        try:
            a = parse_addr(addr)
        except ValueError:
            return old_arg, new, f"{old_arg} is no address"
        old = names.name(a)
        if old is None:
            return old_arg, new, f"the ledger knows no name of {a:#010x} on target {p.target_name}"
        print(f"note: {old_arg} is {old} (the ledger's name on target {p.target_name})")
        given = a
    elif not E.IDENT.match(old_arg):
        return old_arg, new, f"OLD {old_arg!r} is neither a C identifier nor an address (0xADDR, TARGET:0xADDR)"
    else:
        old = old_arg
    if old == new:
        return old, new, f"OLD and NEW are the same name {old}"
    hits = names.by_name.get(old)
    ph = srcscan.PLACEHOLDER_ADDR.fullmatch(old)
    a = given if given is not None else sorted(hits)[0] if hits else (srcscan.placeholder_value(ph) if ph else None)
    kind = "ident"
    if a is not None:
        sym = names.symbol(a)
        sk = sym.value.get("skind") if sym is not None else None
        starts = {f.lo for f in p.store.facts(Kind.start, a, a + 1)}
        kind = "func" if sk in ("func", "thunk") and (sym.lo == a or a in starts) else "data"
    decl_pat = re.compile(DECL_NAME.format(old=re.escape(old)))
    decls = [path for path in sorted((p.root / "decl").glob("*.dcl")) if decl_pat.search(path.read_text())]
    used = E.uses(p.root, old)
    # a symbol with an address is renamed where clang finds it, not where a local, a parameter or a field of the
    # same name stands (srcscan.local_refs); a name without one (a type, a field) by its words
    x = RenamePlan(old_arg, old, new, why, a, kind, a is not None, decls)
    x.used = used
    if not used and not decls:
        if a is not None and a in names.by_name.get(new, ()):
            x.recorded = True
            return x
        return old, new, f"{old} occurs nowhere in src/, include/ or decl/" + (
            f" and {new} is not the ledger's name of {a:#x}" if a is not None else "")
    return x


def check_renames(p, names, plans: list) -> list[tuple[str, str, str]]:
    """The checks of the pairs that need the front end, for all pairs at once (one parse per file that holds
    any of the names, srcscan.local_refs): an OLD found only inside string literals or #include lines, a NEW
    that collides. Sets each plan's `skip` (the occurrences of OLD that are another symbol) and `files` (the
    dry run's replacements per file). The refusals, [] when every pair passes."""
    from .ledger import srcscan
    from .source import edit as E
    exact_used = sorted({x.old for x in plans if x.exact and x.used})
    new_hit = sorted({x.new for x in plans if x.exact and E.code_uses(p.root, x.new)})
    with timing.phase("rename.refs"):
        skip = srcscan.local_refs(p.root, exact_used + new_hit) if exact_used or new_hit else {}
    out = []
    for x in plans:
        x.skip = skip if x.exact and x.used else None
        x.files = E.rename_words(p.root, {x.old: x.new}, dry=True, skip=x.skip) if x.used else {}
        if x.used and not x.files and not x.decls:
            where = ", ".join(f"{f}:{l}" for f, l in x.used[:4])
            out.append((x.old, x.new, f"{x.old} occurs only inside string literals or #include lines ({where}): nothing to "
                                      f"rename (a header file's name is no identifier; edit a string by hand)"))
            continue
        clash = E.code_uses(p.root, x.new, skip if x.exact else None)
        elsewhere = sorted(set(names.by_name.get(x.new, ())) - ({x.a} if x.a is not None else set()))
        if clash and (x.a is None or elsewhere):
            out.append((x.old, x.new, f"{x.new} exists already ({clash[0][0]}:{clash[0][1]})"
                        + (f", the ledger's name at {', '.join(f'{v:#x}' for v in elsewhere)}" if elsewhere else "")
                        + ": refused (a collision)"))
        elif clash:                                 # NEW is OLD's own address's name, written by hand in part
            print(f"note: {x.new} occurs already ({clash[0][0]}:{clash[0][1]}) and names no other address: the rename "
                  f"completes it")
    return out


def write_renames(p, plans: list):
    """Write the checked pairs: one pass over src/ and include/ for all of them (the skip positions were taken
    on the text before any write; one pass keeps them valid where two names share a line), then each pair's
    decl/*.dcl lines. Each plan's `files` becomes what was written for it, `decl_lines` its declaration lines."""
    import re
    from .source import edit as E
    skip: dict = {}
    for x in plans:
        for f, pos in (x.skip or {}).items():
            skip.setdefault(f, set()).update(pos)
    E.rename_words(p.root, {x.old: x.new for x in plans}, skip=skip)
    for x in plans:
        x.decl_lines = 0
        decl_pat = re.compile(DECL_NAME.format(old=re.escape(x.old)))
        for path in x.decls:
            t = path.read_text()
            new, k = decl_pat.subn(x.new, t)
            if k:
                E.write(path, new)
                x.decl_lines += k
                x.files[path.relative_to(p.root).as_posix()] = k
