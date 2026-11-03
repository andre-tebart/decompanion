# Settle gap data through `data fix`

- **Priority:** P1 · **Size:** M-L · **Root:** R7

## Problem

Turning gap data into typed objects takes about 25% of a session (7 sightings). The work is:

- write a typed definition;
- split the GAPDATA block by hand;
- drop the unused `extern GAPDATA` lines;
- handle gap bytes our code now emits as a literal.

## Root cause

- `data fix` D1 only shrinks an array to its room (datafix.rs:14-15).
- It does not split a GAPDATA block around a definition written inside it in another unit.
- It never drops `extern GAPDATA` lines that nothing uses any more.
- A gap block whose bytes our code now writes as a literal leaves two objects of H for one range of I, and nothing
  reports it.

## Task

- D1 and C.overlap between a typed definition and a GAPDATA block, in any unit, are fixed by splitting the block. The
  remainder stays GAPDATA.
- `extern GAPDATA` lines that nothing uses are dropped.
- A gap block covered by a literal is a two-owner finding, and `data fix` drops it.
- D8 on a tiled run (pieces of one unit and section kind, in order and without a hole: an error since the D8 change)
  gets a merge from `data fix`: one definition of the proven extent with the pieces as its fields, the uses rewritten
  to the fields. gildegold had 8 at the change, most of them `full_data_` pieces.
- The worker only writes the one definition with its address comment (H and φ). `data fix --write` resolves the
  contradiction that results.

## Rejected

New commands `settle`, `merge`, `adopt`, `literal`, `trial`, `near`, `check-one`. `dcp why NAME` already lists the
findings at an address.

## Model

Resolving a contradiction by changing H (§5).

## Reports

- data-settle-command (7)
- data-literal-from-gap-block (7)
- data-check-one
- data-struct-from-block-ops
- d8-split-object-is-error (the merge for a tiled D8 run)
