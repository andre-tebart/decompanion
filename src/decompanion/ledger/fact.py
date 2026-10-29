"""The fact model: what the ledger knows about an address interval, and how sure it is.

A Fact says one thing about the bytes [lo, hi) of the original image: its kind names the question (which
section, which symbol, which source, ...), its value answers it, its level says how the answer was obtained,
and `by` names the producer: a rule (`rule:S.crt.code@1`), a line of a declarations file (`decl:decl/text.dcl:17`)
or a line of a source file (`src:src/net/f_10001000.c:1`). Declared facts carry a reason; computed facts carry
their rule's criterion (the rule's docstring, `dcp rules`).

The evidence ladder (Level), from the top:
  proven    forced by bytes: the image alone (a section table, an export, a base relocation), or the image plus
            a compiled artifact compared byte for byte with the relocation fields masked. Wrong only when the
            rule's code is wrong.
  derived   computed by a deterministic rule that rests on a stated convention of the identified toolchain
            (LINK places objects in order; VC6 fill is exactly 90 / CC / 8B FF / 8D 49 00; a direct call target
            is a function start). The convention is named in the rule's docstring.
  declared  a human said so, with a reason. Anything computed from a declared premise is at most declared.
  open      nothing is known. The catch-all rules emit it so the byte map is total.
Levels combine by min: a rule emits at most its ceiling, and at most the lowest level among its premises.
There is no "plausible" and no number: a guess is a declaration with a reason, or it is open.

A Conflict is not a level. It is a record that two facts contradict each other (or a fact contradicts the
bytes); both facts stay in the store, `dcp conflicts` lists them, `dcp check` fails on errors.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any


class Level(IntEnum):
    open = 0
    declared = 1
    derived = 2
    proven = 3

    def __str__(self):
        return self.name


class Kind(StrEnum):
    section = "section"      # {name, chars, raw_lo, raw_hi}; exactly one per mapped byte
    region = "region"        # {what}: pe.header, pe.import_desc, pe.ilt, pe.iat, pe.names, pe.export_*, pe.reloc, pe.rsrc, pad
    symbol = "symbol"        # {skind, name?, extent}; exactly one per byte (unknown.code / unknown.data close the map)
    start = "start"          # {skind: func, how}; a point fact: something starts here (export, entry, call, crt, fptr, decl)
    name = "name"            # {name, origin}; origin: export, import, lib, source, decl, placeholder
    source = "source"        # {file, line, unit, symbol}
    unit = "unit"            # {tu, lib?}
    boundary = "boundary"    # {side: start|end, of: tu}; point fact
    toolchain = "toolchain"  # {compiler, linker, cflags, language}
    ref = "ref"              # {rkind: call|jmp|reloc|operand|fptr, to}; at the site interval
    grade = "grade"          # {code, readability, failing}
    build = "build"          # {tu, ok, obj?, errors}


SYMBOL_KINDS = frozenset((
    "func", "thunk", "fill", "jumptable", "idxtable", "fptr", "global", "string", "float", "guid", "iat",
    "crt.data", "unknown.code", "unknown.data",
))


def canonical(value: Any) -> str:
    """One spelling per value: sorted keys, no spaces, so hashes and equality are stable."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class Fact:
    lo: int
    hi: int
    kind: Kind
    value: dict
    level: Level
    by: str
    reason: str | None = None

    def __post_init__(self):
        if not isinstance(self.kind, Kind):
            object.__setattr__(self, "kind", Kind(self.kind))
        if not isinstance(self.level, Level):
            object.__setattr__(self, "level", Level[self.level] if isinstance(self.level, str) else Level(self.level))
        if self.hi <= self.lo:
            raise ValueError(f"empty interval {self.lo:#x}..{self.hi:#x} for {self.kind}")
        if not self.by:
            raise ValueError("a fact without a producer")
        if self.by.startswith(("decl:", "src:")) and not self.reason:
            raise ValueError(f"declared fact {self.kind} at {self.lo:#x} without a reason ({self.by})")
        if self.kind is Kind.symbol and self.value.get("skind") not in SYMBOL_KINDS:
            raise ValueError(f"unknown symbol kind {self.value.get('skind')!r} at {self.lo:#x}")

    @property
    def size(self):
        return self.hi - self.lo

    def key(self):
        return (self.lo, self.hi, self.kind.value, canonical(self.value))

    def line(self):
        """The one-line spelling `dcp facts` prints."""
        rng = f"{self.lo:#010x}..{self.hi:#010x}" if self.hi > self.lo + 1 else f"{self.lo:#010x}"
        vals = "  ".join(f"{k}={fmt_value(v)}" for k, v in sorted(self.value.items()))
        s = f"{rng}  {self.kind.value}  {vals}  {self.level}  by={self.by}"
        if self.reason:
            s += f"  reason={self.reason!r}"
        return s


def fmt_value(v):
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return f"{v:#x}" if v >= 0x1000 else str(v)
    if isinstance(v, list):
        return ",".join(fmt_value(x) for x in v)
    if isinstance(v, str) and (" " in v or not v):
        return repr(v)
    return str(v)


class Severity(StrEnum):
    bug = "bug"       # proven contradicts proven: a rule is wrong
    error = "error"   # a declared or derived fact contradicts something above open; the gate fails
    warn = "warn"     # worth a look, no gate


@dataclass(frozen=True, slots=True)
class Conflict:
    severity: Severity
    check: str            # the check id, e.g. C.overlap, L3, M8
    lo: int
    hi: int
    message: str
    a: str = ""           # producer of the first fact (its `by`), when there is one
    b: str = ""           # producer of the second

    def __post_init__(self):
        if not isinstance(self.severity, Severity):
            object.__setattr__(self, "severity", Severity(self.severity))

    def line(self):
        rng = f"{self.lo:#010x}..{self.hi:#010x}" if self.hi > self.lo + 1 else f"{self.lo:#010x}"
        s = f"{self.severity}  {self.check}  {rng}  {self.message}"
        if self.a:
            s += f"  a={self.a}"
        if self.b:
            s += f"  b={self.b}"
        return s


def severity_of(a: Level, b: Level) -> Severity:
    """The severity of a contradiction between two facts, from their levels (open never conflicts)."""
    if a is Level.proven and b is Level.proven:
        return Severity.bug
    return Severity.error


def min_level(*levels: Level, ceiling: Level = Level.proven) -> Level:
    """The level a conclusion may carry: the rule's ceiling, lowered by its premises."""
    return min((ceiling, *levels))
