# An unbuilt function's experiment is "not run"

- **Priority:** P0 · **Size:** M · **Root:** R6

## Problem

One unit that fails to compile gives about 80 `M1 ... byte -> draft` lines, which bury the single M.compile cause.

## Root cause

- rules.rs:186-193 turns "no object: the unit failed to compile" into a draft row.
- M1 (layout.rs:798-801) then sees a fall for each of those functions.
- The line `FAILED units=... the grades above count their functions as unbuilt` (clicmd.rs:889-895) patches over the
  same conflation.

## Task

- G.grade records an unbuilt function as experiment *not run* (open), not as draft.
- M1 skips functions whose premise, the unit's object, is missing. It emits one finding per unit instead: "unit X does
  not compile (M.compile): N baseline functions have no experiment". M.compile keeps the gate failing.
- Remove the FAILED-units patch line.
- Sweep the other rules for ones that substitute draft or 0 for "not run".

## Model

§3, §4: no observation means open, not a failed experiment.

## Reports

- check-compile-failure-floods-m1
- build-unit-silently-dropped (the M1 part)
