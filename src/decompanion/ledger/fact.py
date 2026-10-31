"""The fact model's names: what the ledger knows about an address interval, and how sure it is.

A fact says one thing about the bytes [lo, hi) of the original image: its kind names the question (which section,
which symbol, which source, ...), its value answers it, its level says how the answer was obtained, and `by` names
the producer: a rule (`rule:S.crt.code@1`), a line of a declarations file (`decl:decl/text.dcl:17`) or a line of a
source file (`src:src/net/f_10001000.c:1`). Declared facts carry a reason; computed facts carry their rule's
criterion (`dcp rules -v`).

The evidence ladder (Level), from the top:
  proven    forced by bytes: the image alone (a section table, an export, a base relocation), or the image plus
            a compiled artifact compared byte for byte with the relocation fields masked. Wrong only when the
            rule's code is wrong.
  derived   computed by a deterministic rule that rests on a stated convention of the identified toolchain
            (LINK places objects in order; VC6 fill is exactly 90 / CC / 8B FF / 8D 49 00; a direct call target
            is a function start). The convention is named in the rule's criterion.
  declared  a human said so, with a reason. Anything computed from a declared premise is at most declared.
  open      nothing is known. The catch-all rules emit it so the byte map is total.
Levels combine by min: a rule emits at most its ceiling, and at most the lowest level among its premises.
There is no "plausible" and no number: a guess is a declaration with a reason, or it is open.

A conflict is not a level. It is a record that two facts contradict each other (or a fact contradicts the bytes);
both facts stay in the store, `dcp conflicts` lists them, `dcp check` fails on errors.

The facts, their checks and their spelling are the core's (native/dcp_core/src/store.rs, engine.rs, clicmd.rs);
these are the names the store's face hands out.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


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
    start = "start"          # {skind: func, how}; a point fact: something starts here
    name = "name"            # {name, origin}; origin: export, import, lib, entry, source, decl
    source = "source"        # {file, line, unit, symbol}
    unit = "unit"            # {tu, lib?} (library members) / {tu, status, start_level, end_level, ...} (game units)
    boundary = "boundary"    # {side: start|end, tu, named_by?}; point fact
    toolchain = "toolchain"  # {compiler, linker, cflags, language}
    ref = "ref"              # {rkind: call|jmp|reloc|operand|fptr, to}; at the site interval
    grade = "grade"          # {code, readability, failing}
    build = "build"          # {tu, ok, obj?, errors}
    evidence = "evidence"    # {ekind: lit|fill|leak, ...}: computed layout evidence, never a claim by itself


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
