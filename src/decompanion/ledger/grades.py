"""The grades as the commands read them (the `grade` facts of G.grade, rules/grade.py): the queues, the
baseline, the level ladder.

Queues (ported from the first attempt's ledger/grade.py work_items; units are the separated game units of
L.unit.extent, a unit's functions the grade facts of its functions):
  base   every function below shape + readable without a level tag. Every code draft comes before any
         readability-only work: first the draft functions, units with the fewest drafts first, then the
         functions at shape / byte that are not readable, units with the fewest such functions first; address
         order inside a unit.
  deep   every function with @deep or @stuck, plus every function below byte + readable of a unit whose base
         work is done (no base item left). Units by the total distance (differing instructions) of their items,
         smallest first; inside a unit the closest function first; @stuck functions after everything else. An
         escalated function that is byte already and only fails readability (a Q-only item) waits behind its
         unit's byte work and is the names queue's.
  names  the Q-only deep functions (level deep or stuck, code byte, not readable), the deep queue's unit order.
Shards: a unit belongs to the shard k of N with the largest sha1("<unit start>:<k>") (rendezvous hashing: the
split does not depend on the queue order and moves ~1/N of the units when N changes). `--shard k/N`, else the
file .dcp/shard (one line `k/N`), else no shard.

The level ladder: `@deep why` / `@stuck why` in the address comment (`dcp escalate`, `dcp stuck`, `--clear`).
`dcp escalate` refuses a reason that names only missing statements (reconstruction is base work). A tag on a
function that reached byte + readable is removed by `dcp build` (auto-clear).

The baseline ledger/grades.tsv (target, address, name, unit, code, readability, level, accepted; a header
line; sorted by target in config order, then address) is written only by `dcp promote` and `dcp accept` on the
main checkout; M1 compares against it, `dcp check --against REV` against its version at a git revision.
`dcp promote` raises entries only: a fall against the baseline is refused (listed, nothing written) unless
`--accept-falls`. `dcp accept FN --to GRADE --why TEXT` lowers one entry and fills its accepted column
(`byte+readable -> shape+readable at <commit>: <why>`); promote keeps the column while the function stays below
the grade it fell from and clears it once it is back.

The queues, the shards, the baseline and the level ladder's edits are the core's (native/dcp_core/src/queues.rs);
this module is their face.
"""
from __future__ import annotations

from pathlib import Path

from .. import native

_core = native.core()
HEADER = "target\taddress\tname\tunit\tcode\treadability\tlevel\taccepted"
SHARD_FILE = Path(".dcp") / "shard"
CODE_RANK = {c: i for i, c in enumerate(("draft", "shape", "byte"))}


def function_grades(store) -> list[dict]:
    """The function grade rows (the grade fact's value with addr and by), by address."""
    return _core.grades_function(store._p)


def unit_grades(store) -> list[dict]:
    return _core.grades_unit(store._p)


def parse_shard(text: str) -> tuple[int, int] | None:
    """'k/N' -> (k, N); 'off' -> None."""
    return _core.grades_parse_shard(text)


def shard_setting(root: Path, arg: str | None) -> tuple[int, int] | None:
    if arg:
        return parse_shard(arg)
    p = Path(root) / SHARD_FILE
    return parse_shard(p.read_text()) if p.exists() else None


def shard_owner(start: int, n: int) -> int:
    """The shard of a unit among n: rendezvous hashing of its start address."""
    return _core.grades_shard_owner(start, n)


def queue(store, which: str = "base", shard: tuple[int, int] | None = None, unit: str | None = None) -> list[dict]:
    """The items of the base / deep / names queue in order (module docstring); each a function grade row with
    `queue_unit` and `section` (draft / read for base, deep / stuck for deep and names)."""
    return _core.grades_queue(store._p, which, shard, unit)


# ------------------------------------------------------------------------------------------------ the level ladder
def only_missing_statements(reason: str) -> bool:
    """True when every clause of the reason speaks of missing or unwritten statements: reconstruction is base
    work, not a reason to escalate."""
    return _core.grades_only_missing_statements(reason)


# ------------------------------------------------------------------------------------------------ baseline
def parse_baseline(text: str) -> dict[tuple[str, int], dict]:
    """(target, address) -> {name, unit, code, readability, level, accepted} of a ledger/grades.tsv text."""
    return _core.grades_parse_baseline(text)


def grade_of(r) -> str:
    """`code+readability` of a grade row."""
    return f"{r['code']}+{r['readability']}"


def at_least(r, grade: str) -> bool:
    """True when a grade row is at or above `code+readability` in both dimensions."""
    return _core.grades_at_least(r["code"], r["readability"], grade)


def accept_note(before: str, after: str, commit: str, why: str) -> str:
    """The accepted column: `byte+readable -> shape+readable at 897b411: why`."""
    return _core.grades_accept_note(before, after, commit, why)


def note_from(note: str) -> str | None:
    """The grade an accepted fall came from (None for an empty or unreadable column)."""
    return _core.grades_note_from(note or "")


def baseline_text(projects, old: str = "", accept_falls: bool = False, commit: str = "-") -> str:
    """The text of ledger/grades.tsv from the current grades of every target (projects in config order)."""
    return _core.grades_baseline_text([(p.target_name, p.store._p) for p in projects], old, accept_falls, commit)


def accept(text: str, target: str, addr: int, code: str, readability: str, note: str) -> str:
    """The baseline text with one function's entry lowered to `code` + `readability` and its accepted column set."""
    return _core.grades_accept(text, target, addr, code, readability, note)


def commit_of(root: Path) -> str:
    """The short hash of HEAD ('-' outside a git checkout)."""
    return _core.grades_commit_of(str(root))


def baseline_at(root: Path, rev: str) -> str:
    """ledger/grades.tsv at a git revision ('' when it has none)."""
    return _core.grades_baseline_at(str(root), rev)


def regressions(project, text: str) -> list[str]:
    """The falls of the current target's function grades against a baseline text."""
    return _core.grades_regressions(project.target_name, project.store._p, text)
