# Frame-slot annotation in disasm and asmdiff

- **Priority:** P1 · **Size:** M

## Problem

Workers subtract push depth by hand to read `[esp+X]` operands. Worker 48 put this at 30-40% of a session, and there
are about 12 sightings. Slots that are read but never written, and arguments left pending across a call, are hard to
see.

## Root cause

esp operands are shown raw. The prover already tracks `SP0+c` per instruction and `Var::Undef` for slots that are
never written.

## Task

- disasm and asmdiff annotate esp-based operands with an entry-relative slot or argument: `{S-0x10}`, `{arg2}`.
- Mark a slot that is read but never written, and arguments pending across a call.
- On by default; no new command.

## Rejected

- A `dcp frame` command.
- Slot-sharing hints. "Try inner-block locals" goes to the VC6 spellings reference (skills-sync-and-fixes).

## Model

Reading I: an analysis that produces no claims.

## Reports

- frame-slot-layout (about 12)
- uninitialized-frame-read-hint
- diffclass-arg-slot-reuse-class (diagnosis)
- detect-nested-call-in-arguments (visibility)
