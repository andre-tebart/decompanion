# Declaration-set tie-breaks: measure them, attribute them to the unit

- **Priority:** P0 (interrupts the workflow) · **Size:** M

## Problem

- VC6's register allocation breaks ties by the declaration set a unit sees. A correct type change in a widely
  included header (a union member, a field, even an unused typedef) moves functions that never use that type
  between byte, shape and draft.
- Seen in gildegold's Q4 typing (2026-11-04): d3_CloneObject (any change to d3_fl.h or d3.h's D3PARTSYS),
  ai_TutorialInitChapter2 and ai_TutorialInitChapter3 (any change to ai_types.h), ai_Unk483a60 (flips shape ->
  byte -> shape). Workers either picked a worse spelling to dodge it, or reverted a correct type.
- Every header change produces one fall per sensitive function, and each asks for a reaction (dodge, revert, debt).
  The cause is the same each time and known in advance: this is noise, and it interrupts the typing work.
- ai_TutorialInitChapter3 falls to *draft*, not shape. Its "code" hunks are the same stores of the same float
  constants (0x420c0000 / 0x428e0000 / 0x430e0000 at [esi+0x64]+0x20..0x28): the registers are permuted and the
  constant loads reordered. diffclass does not see this as allocation.
- The automatic tag removal (`grades_auto_clear`) flips with these functions: an `@deep` note is cleared when the
  function goes byte by accident, then the function falls back (gildegold 8f3bcdb1 / be7af8e3 / 66b329b8). That is
  a misleading verdict.

## Model

§4: an experiment tests one thing and masks what belongs to something else. A tie-break comes from the unit's
declaration set, not the function's source, so the object experiment is reporting on the headers. §8.6: many small
shifts share one cause; here the cause can be measured before it fires.

## Task

- **Probe (the experiment):** trial-compile a unit with a no-meaning perturbation prepended to its preamble: one
  unused typedef (`typedef int __dcp_probe_1;`), then two with other names. A function whose bytes change under any
  probe is tie-break sensitive. A change is proof, so this is an observation, not a guess. Reuse the trial
  machinery (`datafix.rs` Trial, `headers conflicts --trial`, build/obj/trial/). Cost: one compile per unit per
  probe, run on a fall of a unit's function and as a batch (`dcp headers probe [UNIT]` or similar), nothing on a
  warm read.
- **Record it:** a derived `tiebreak` claim per function with its probe witness, in the ledger. Never hand-written.
  It goes stale when the function's text changes; the next fall re-probes.
- **Attribute the fall:** a `tiebreak` function that moves after a declaration change that leaves its own text
  unchanged gets no M1 fall line and needs no debt item. M1 and the wrap print one line per changed header instead:
  `tie-break: N functions moved (ai_types.h)`, named by cause.rs (the changed headers of the unit's include closure, with the chain, the uncommitted ones first).
- **Grade stays honest:** byte / shape / draft as built, no tolerance. The function's best grade under the probes is
  recorded as its source-proven grade. The remaining gap is a unit-level finding ("declaration set not yet the
  original's"), not base or deep queue work: `tiebreak` functions at source-proven byte leave both queues.
- **diffclass:** a code hunk whose two sides store the same values to the same places, with constants loaded into
  permuted registers in another order, is `regs` + `order` (allocation), not `code`. Then a tie-break fall is
  at most shape.
- **Auto-clear:** do not clear a tag on a `tiebreak` function; a byte reached through the declaration set proves
  nothing about its source.
- **First check:** run the probe on gildegold's four functions. If one typedef already moves all four, the count
  drives the tie-break; if only some names do, it is a hash and the probe family needs more variants.
  - First sighting (2026-11-04, gildegold 98e0c0f3): `typedef int __dcp_probe_1;` after ai_types.h's guard raised
    ai_TutorialInitChapter2 from shape (its debt grade) to byte; Chapter3 stayed draft. The same line in d3_fl.h left
    d3_CloneObject at byte. One typedef is not enough for every function: the family needs more variants (two,
    three, other names), and a probe must also look for raises, not only falls.

## Endgame

The `tiebreak` functions are the oracle for the original header layout: they are the ones that say when a unit's
declaration set is right. The re-match pass (§8.6) runs them last, once the headers settle.

## Rejected

- Hiding the fall (a tolerance for byte -> shape): the build grade stays what the build gives; only the attribution
  and the queue change.
- Choosing headers to keep a match: the declaration set is H's to get right, not a lever for the grade. The probe
  never changes what H means.
- Inferring the cause from "names it does not use" alone: needs name-use analysis and still fires per change. The
  probe measures the sensitivity once.
