# Declaration-set tie-breaks: name them, and classify their hunks as allocation

- **Priority:** P1 · **Size:** M

## Problem

- VC6's register allocation breaks ties by the declaration set a unit sees. A correct type change in a widely
  included header (a union member, a field, even an unused typedef) moves functions that never use that type
  between byte, shape and draft.
- Seen in gildegold's Q4 typing (2026-11-04): d3_CloneObject (any change to d3_fl.h or d3.h's D3PARTSYS),
  ai_TutorialInitChapter2 and ai_TutorialInitChapter3 (any change to ai_types.h), ai_Unk483a60 (flips shape ->
  byte -> shape). Workers either picked a worse spelling to dodge it, or reverted a correct type.
- ai_TutorialInitChapter3 falls to *draft*, not shape. Its "code" hunks are the same stores of the same float
  constants (0x420c0000 / 0x428e0000 / 0x430e0000 at [esi+0x64]+0x20..0x28): the registers are permuted and the
  constant loads reordered. diffclass does not see this as allocation.
- The automatic tag removal (`grades_auto_clear`) flips with these functions: an `@deep` note is cleared when the
  function goes byte by accident, then the function falls back (gildegold 8f3bcdb1 / be7af8e3 / 66b329b8).

## Task

- **diffclass:** a code hunk whose two sides store the same values to the same places, with constants loaded into
  permuted registers in another order, is `regs` + `order` (allocation), not `code`. Then a tie-break fall is
  at most shape.
- **Name the cause:** a fall whose function's source and include set are unchanged, after a declaration change in a
  header it includes but whose names it does not use, gets an M1 note ("declaration-set tie-break: <header>").
  The evidence is the trial (`dcp headers conflicts --trial` already compiles such variants, §8.5).
- **Auto-clear:** do not clear a tag on a byte reached only through a declaration-set change of this kind.

## Rejected

- Hiding the fall (a tolerance for byte -> shape): the experiment's outcome is what it is. The debt records it.
- Choosing headers to keep a match: the declaration set is H's to get right, not a lever for the grade.
