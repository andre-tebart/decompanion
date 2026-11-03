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
  gets a merge from `data fix`: one definition of the object with the pieces as its offsets, the uses rewritten to
  them. What gildegold's eight taught (its commit 1effcf3b, settled by hand):
  - D8's range is a lower bound, not the object. A loop's evidence starts at the first field it touches: four of the
    tables began 4..0xc bytes earlier (0x62d148 not 0x62d14c, 0x6f40e0 not 0x6f40e4, 0x6f4f00 / 0x6f52e0 not
    +0xc). The start follows from the stride: every accessed field inside a row, the rows ending at the next object.
    The merge takes that start and cuts the piece before it there (the string before 0x62d148 kept its 0x14 bytes).
  - A piece used only as a loop's one-past bound (`p < (unsigned)full_data_X`) is no object. The gap block split at
    eleven such addresses; their uses become `table + size + field`, and their bytes join the gap they lie in. Find
    them as a check: a gap piece whose every use is a bound of a loop over the table before it.
  - A bound may be spelled through another object entirely: `(unsigned)ai_FallbackBuilding + 0x2c50` (the pointer's
    value plus an offset) for 0x6f4f5c. The rewrite keys on the address the original's `cmp` holds.
  - Not every D8 is a split: main_Family's was the original's memset overrunning the record (decl `overrun`).
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
