"""Grades (G.*): two grades per (function, target), computed, nothing typed by hand (lifted from the first
attempt's ledger/grade.py; "behaviour" is called "shape" here: a diff explained by register, slot and
scheduling classes proves the same shape, not the same behaviour).

  code          draft -> shape -> byte       what our compiled function is against the original's bytes
  readability   draft -> readable            whether a reader can follow the C without the disassembly

Code rules:
  B1 byte    M.match holds for the function (masked bytes equal, the original ends where we end, the DLL aid).
  B2 shape   the bytes differ, but every differing hunk of the instruction diff (match/diffclass.py) is `fill`,
             `order`, or explained by the ISA (`regs`, `slots`, `order` after a register renaming, `sib`,
             `fpu`) or `frame` (stack offsets shifted by a frame of another size); or the instructions left in
             the `code` hunks are the same multiset on both sides; or the whole function is equal under one
             bijective renaming of registers and stack slots; and every jump inside the function goes to the
             instruction the alignment pairs with the original's target, or to an identical copy of its
             epilogue (diffclass's branch targets: the listing reads a target as X); and the switch tables,
             when both sides have them, are equal as data. Identical instruction text (a byte difference in a
             relocated field only, or a branch displacement whose target aligns) is shape too. Not a proof of
             equal behaviour: what the instruction diff can see. The original is read over the function's extent (the code
             walk's, else L.src.extent's) up to its first switch table (diffclass.compare_function).
  B3 draft   a `code` hunk, a `branch` or a `table` difference B2 does not explain remains, or the function has
             no compiled object to compare.
Readability rules, on the function's text (comments and strings blanked for the code tests):
  Q1 name         the function's own name is no placeholder (`Unk` + 4 hex digits, or ending in 6 hex digits with
                  a digit among them: FUN_10008d20, Unk10008d20, thread_10008d20).
  Q2 identifiers  no placeholder identifier in the definition: the Q1 forms, `param_N`, `xVarN`, `local_N`,
                  `DAT_` / `PTR_` / `FUN_` / `LAB_` names, `unk` / `unk_` + hex.
  Q3 addresses    no integer literal inside the image's address range in the code.
  Q4 raw access   no `*(T *)` dereference-cast, and no use of a macro any source or header defines with one
                  (a function-like one, or an object-like `(*(T ...` one that is no view with an address
                  comment: a view is a named part of a data object, srcscan View: `(*(T *)&datum)` or
                  `(*(T *)((char *)&datum + OFF))` with the address comment on its line; `(*(T *)datum)` is raw).
                  The message states the accepted view form.
  Q5 markers      no draft marker in the address comment or the body: ROUGH, SKELETON, TODO, FIXME, XXX
                  (whole words) or the `@rough` tag.
  Q6 described    the address comment carries text after the address, or another comment of any source or
                  header starts with the function's address and carries text after it.
  Q7 prototypes   every call goes through a prototype (clang lint, `dcp lint`): evaluated only when a lint run
                  is recorded for the target (input `lint`); without one Q7 is not evaluated and says so.
  Q8 complete     our compiled code is at least half the original's code size (the walk's or the source
                  extent's): a stub (`void f(void) {}`) or an unfinished body cannot be followed as the original,
                  however good its names (without it a named, described stub graded readable).
Unit grades: code = the lowest code grade of its functions; readable only when every function is readable
and the unit's name has an origin other than `guess` (its start boundary's `by=`).
"""
from __future__ import annotations

import functools
import json
import re

from ..build import compile as build_compile
from ..ledger import srcscan
from ..ledger.fact import Level
from .engine import RuleContext, rule
from .match import WALK

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open
CODE = ("draft", "shape", "byte")
READ = ("draft", "readable")
CODE_RANK = {c: i for i, c in enumerate(CODE)}

DEREF_CAST = re.compile(r"\*\s*\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*"
                        r"(?:\s+[A-Za-z_]\w*)*\s*\*+\s*(?:const\s*)?\)")


@functools.lru_cache(maxsize=2)
def context(root: str, tree: str) -> tuple[frozenset, frozenset]:
    """(raw macro names (Q4), described addresses (Q6)) over every source and header of the tree (collected by
    the source scan, per file)."""
    sc = srcscan.scan(root, tree)
    defs = {}
    for name, body in sc.macros:
        defs.setdefault(name, body)
    described = set(sc.described)
    obj = set(sc.rawobj)                              # object-like: used without a call
    raw = {n for n, body in defs.items() if DEREF_CAST.search(body)} | obj
    while raw:
        fn = sorted(map(re.escape, raw - obj))
        pat = re.compile("|".join(([r"\b(" + "|".join(fn) + r")\s*\("] if fn else [])
                                  + ([r"\b(" + "|".join(sorted(map(re.escape, obj))) + r")\b"] if obj else [])))
        more = {n for n, body in defs.items() if n not in raw and pat.search(body)}
        if not more:
            break
        raw |= more
    return frozenset(raw), frozenset(described)


# ------------------------------------------------------------------------------------------------ M1
def parse_baseline(text: str) -> dict[tuple[str, int], dict]:
    """(target, address) -> {name, unit, code, readability, level, accepted} of a ledger/grades.tsv text (a
    header line and one tab-separated line per function: target, address, name, unit, code, readability, level,
    accepted; the last column, empty unless `dcp accept` lowered the entry, may be missing in an older file)."""
    out = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith(("#", "target\t")):
            continue
        f = line.split("\t")
        f += [""] * (8 - len(f))
        try:
            a = int(f[1], 16)
        except ValueError:
            continue
        out[(f[0], a)] = {"name": f[2], "unit": f[3], "code": f[4], "readability": f[5], "level": f[6], "accepted": f[7]}
    return out


def falls(base: dict, now: dict | None) -> list[str]:
    """What fell from a baseline row to the current grade (None: the function has no grade any more)."""
    if now is None:
        return [f"graded {base['code']} + {base['readability']} in the baseline, no grade now (its source is gone?)"]
    out = []
    if base["code"] in CODE_RANK and CODE_RANK[now["code"]] < CODE_RANK[base["code"]]:
        out.append(f"code {base['code']} -> {now['code']}")
    if base["readability"] == "readable" and now["readability"] != "readable":
        out.append("readability readable -> draft")
    return out

