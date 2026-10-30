"""The grades as the commands read them (the `grade` facts of G.grade, rules/grade.py): the queues, the
baseline, the level ladder.

Queues (ported from the first attempt's ledger/grade.py work_items; units are the separated game units of
L.unit.extent, a unit's functions the grade facts of its fragments):
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

The baseline ledger/grades.tsv (target, address, name, unit, code, readability, level; a header line; sorted
by target in config order, then address) is written only by `dcp promote` on the main checkout; M1 compares
against it, `dcp check --against REV` against its version at a git revision.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .. import fsmemo
from ..rules.grade import CODE_RANK, falls, parse_baseline
from . import srcscan
from .fact import Kind

HEADER = "target\taddress\tname\tunit\tcode\treadability\tlevel"
SHARD_FILE = Path(".dcp") / "shard"


def function_grades(store) -> list[dict]:
    out = []
    for f in store.facts(Kind.grade):
        if f.value.get("of") == "function":
            out.append(dict(f.value, addr=f.lo, by=f.by))
    return sorted(out, key=lambda r: r["addr"])


def unit_grades(store) -> list[dict]:
    return sorted((dict(f.value, lo=f.lo, hi=f.hi) for f in store.facts(Kind.grade) if f.value.get("of") == "unit"),
                  key=lambda r: r["lo"])


def game_units(store) -> list[dict]:
    """The game units (L.unit.extent): {tu, lo, hi, status, named_by}."""
    return sorted(({"tu": f.value["tu"], "lo": f.lo, "hi": f.hi, "status": f.value["status"], "named_by": f.value.get("named_by")}
                   for f in store.facts(Kind.unit) if "status" in f.value), key=lambda u: u["lo"])


def below_shape(r) -> bool:
    return r["code"] == "draft" or r["readability"] != "readable"


def below_byte(r) -> bool:
    return r["code"] != "byte" or r["readability"] != "readable"


def q_only(r) -> bool:
    return r["level"] in ("deep", "stuck") and r["code"] == "byte" and r["readability"] != "readable"


# ------------------------------------------------------------------------------------------------ shards
def parse_shard(text: str) -> tuple[int, int] | None:
    """'k/N' -> (k, N); 'off' -> None."""
    text = text.strip()
    if text == "off":
        return None
    m = re.fullmatch(r"(\d+)/(\d+)", text)
    if not m or not 0 <= int(m.group(1)) < int(m.group(2)):
        raise ValueError(f"a shard is k/N with 0 <= k < N (or off), not {text!r}")
    return int(m.group(1)), int(m.group(2))


def shard_setting(root: Path, arg: str | None) -> tuple[int, int] | None:
    if arg:
        return parse_shard(arg)
    p = Path(root) / SHARD_FILE
    return parse_shard(p.read_text()) if p.exists() else None


def shard_owner(start: int, n: int) -> int:
    """The shard of a unit among n: rendezvous hashing of its start address."""
    return max(range(n), key=lambda k: hashlib.sha1(f"{start:#010x}:{k}".encode()).digest())


# ------------------------------------------------------------------------------------------------ queues
def queue(store, which: str = "base", shard: tuple[int, int] | None = None, unit: str | None = None) -> list[dict]:
    """The items of the base / deep / names queue in order (module docstring); each a function grade row with
    `queue_unit` and `section` (draft / read for base, deep / stuck for deep and names)."""
    rows = function_grades(store)
    by_unit: dict[str, list[dict]] = {}
    for r in rows:
        by_unit.setdefault(r["unit"], []).append(r)
    units = [u for u in game_units(store) if u["status"] == "separated" and u["tu"] in by_unit]
    if unit:
        units = [u for u in units if u["tu"] == unit]
    elif shard:
        units = [u for u in units if shard_owner(u["lo"], shard[1]) == shard[0]]
    dist = lambda r: (r.get("dist") or {}).get("ins") or 0  # noqa: E731
    if which == "base":
        drafts, reads = [], []
        for u in units:
            base = [r for r in by_unit[u["tu"]] if below_shape(r) and not r["level"]]
            d = [dict(r, queue_unit=u["tu"], section="draft") for r in base if r["code"] == "draft"]
            rd = [dict(r, queue_unit=u["tu"], section="read") for r in base if r["code"] != "draft"]
            if d:
                drafts.append((len(d), u["lo"], d))
            if rd:
                reads.append((len(rd), u["lo"], rd))
        drafts.sort(key=lambda x: (x[0], x[1]))
        reads.sort(key=lambda x: (x[0], x[1]))
        return [it for *_, items in drafts for it in items] + [it for *_, items in reads for it in items]
    per = []
    for u in units:
        rs = by_unit[u["tu"]]
        base_left = any(below_shape(r) and not r["level"] for r in rs)
        all_items = [r for r in rs if r["level"] in ("deep", "stuck") or (not base_left and below_byte(r))]
        byte_items = [r for r in all_items if not q_only(r)]
        if which == "names":
            items = [r for r in all_items if q_only(r)]
        else:
            items = byte_items or [r for r in all_items if q_only(r)]
        items = sorted(items, key=lambda r: (dist(r), r["addr"]))
        if items:
            per.append((0 if byte_items else 1, sum(dist(r) for r in byte_items), u["lo"],
                        [dict(r, queue_unit=u["tu"], section="stuck" if r["level"] == "stuck" else "deep") for r in items]))
    per.sort(key=lambda x: (x[0], x[1], x[2]))
    flat = [it for *_, items in per for it in items]
    return [r for r in flat if r["section"] != "stuck"] + [r for r in flat if r["section"] == "stuck"]


# ------------------------------------------------------------------------------------------------ the level ladder
MISSING = re.compile(r"\b(missing|absent|lacks?|lacking|reconstruct\w*|unwritten|not\s+(?:yet\s+)?written|add(?:ed)?)\b", re.I)
STATEMENTS = re.compile(r"\b(statements?|bod(?:y|ies)|calls?|branch(?:es)?|loops?|cases?|code|lines?)\b", re.I)


def only_missing_statements(reason: str) -> bool:
    """True when every clause of the reason (split at `;` `,` `.` and the word `and`) speaks of missing or
    unwritten (missing, absent, lacking, reconstruct, unwritten, not written, add) statements, bodies, calls,
    branches, loops, cases, code or lines: reconstruction is base work, not a reason to escalate."""
    clauses = [c.strip() for c in re.split(r"[;,.]|\band\b", reason) if c.strip()]
    return bool(clauses) and all(MISSING.search(c) and STATEMENTS.search(c) for c in clauses)


DEEP = re.compile(r"[ \t]*@deep\b[^@*\n]*")
STUCK = re.compile(r"[ \t]*@stuck\b[^@*\n]*")


def set_level(root: Path, rel: str, level: str | None, reason: str | None) -> str:
    """Write `@<level> reason` into the address comment (line 1) of the fragment `rel`, replacing a @deep or
    @stuck tag already there; level None removes either tag. Returns what was done."""
    p = Path(root) / rel
    text = p.read_text()
    S = srcscan.Source(rel, text)
    if not S.comments or S.comments[0][0] != 0 and text[:S.comments[0][0]].strip():
        raise ValueError(f"{rel}: no address comment on line 1")
    cs, ce, body = S.comments[0]
    raw = text[cs:ce]
    old = "@deep" if DEEP.search(body) else "@stuck" if STUCK.search(body) else None
    stripped = STUCK.sub("", DEEP.sub("", body)).rstrip()
    if level is None:
        if old is None:
            return "no @deep or @stuck tag"
        new_body, action = stripped, f"{old} removed"
    else:
        reason = (reason or "").replace("*/", "* /").strip()
        new_body = stripped + f" @{level} {reason}"
        action = f"@{level} added" if old is None else (f"@{level} reason replaced" if old == "@" + level else f"{old} -> @{level}")
    if raw.startswith("/*"):
        new_raw = "/*" + new_body + " */"
    else:
        new_raw = "//" + new_body
    p.write_text(text[:cs] + new_raw + text[ce:], newline="\n")
    fsmemo.wrote(p)
    return action


def auto_clear(project, rows) -> list[str]:
    """Remove the level tag of every function that reached byte + readable; one line per change."""
    out = []
    for r in rows:
        if r["level"] and r["code"] == "byte" and r["readability"] == "readable":
            action = set_level(project.root, r["file"], None, None)
            out.append(f"auto-clear {r['file']}: {r['name']} is byte + readable, {action}")
    return out


# ------------------------------------------------------------------------------------------------ baseline
def baseline_text(projects) -> str:
    """The text of ledger/grades.tsv from the current grades of every target (projects in config order)."""
    lines = [HEADER]
    for p in projects:
        for r in function_grades(p.store):
            lines.append("\t".join((p.target_name, f"{r['addr']:#010x}", r["name"], r["unit"], r["code"], r["readability"], r["level"])))
    return "\n".join(lines) + "\n"


def baseline_at(root: Path, rev: str) -> str:
    """ledger/grades.tsv at a git revision ('' when it has none)."""
    r = subprocess.run(["git", "show", f"{rev}:ledger/grades.tsv"], cwd=root, capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def regressions(project, text: str) -> list[str]:
    """The falls of the current target's function grades against a baseline text."""
    base = {a: r for (t, a), r in parse_baseline(text).items() if t == project.target_name}
    now = {r["addr"]: r for r in function_grades(project.store)}
    out = []
    for a, r in sorted(base.items()):
        for what in falls(r, now.get(a)):
            out.append(f"{a:#010x} {r['name']}: {what}")
    return out


__all__ = ["CODE_RANK", "function_grades", "unit_grades", "queue", "set_level", "auto_clear", "baseline_text", "regressions"]
