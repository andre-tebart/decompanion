# Slot pairing by object: a wrong local-array index is no slot renaming

- **Priority:** P0 · **Size:** M · **Root:** R2
- **Related:** frame-slot-annotation (the slot model), prover-coverage

## Problem

From bug-reports/shape-grade-hides-wrong-array-index.md (gildegold match-base, 2026-11-07). `ai_BuildingDetailWindow`
read `balance[0x11]` where the original reads `balance[0]`, and the grade said **shape**: `slots 2`. The wrong index
was only a different `[esp+X]` on a load from the local array, and diffclass reads any esp displacement pair as a
frame-slot renaming. The same class as gildegold's amt_Rating record-offset bug, which crashed the game.

## Task

- The slot pairing is one consistent map over the whole function, not per hunk: `[esp+X]` -> `[esp+Y]` holds for
  every access (push depth taken off, the entry-relative slot of frame-slot-annotation). A pair that contradicts the
  function's map is a `code` hunk.
- Where the frame layout is known (our object's debug-free frame: the locals' sizes from the front end, or the
  extents both sides' accesses imply), a slot is (local, offset in it). Renaming the local is a slot hunk. Another
  offset within the paired local is a meaning difference (`const` class of diffclass-meaning-classes).
- The prover's frame correspondence follows the same rule: two offsets of one local never pair with one offset.
- Measure on gildegold: the shape functions whose verdict needs a slots hunk. Any that fall to draft are bug
  candidates to read by hand.

## Reports

- shape-grade-hides-wrong-array-index (bug)
