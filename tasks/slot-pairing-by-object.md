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

## First slice (2026-11-09): M.slotmap, a warning

src/slotmap.rs, run by G.grade for every function that is no byte match. The entry-relative esp depth of each
instruction comes from a walk of the code (pushes, `sub` / `add esp`, stdcall callees through memory). The listings
are aligned with each stack operand read as its entry-relative slot, so frames of other sizes line up. An array is a
slot whose address is taken or that is indexed, up to the next one. Per pair of arrays the correspondence is the
offset difference most accesses agree on. A plain access is listed when it is off that correspondence (and off the
base pairing), the element it reaches is paired by the correspondence elsewhere, and its hunk is no crosswise
pairing of reordered code (the same elements on both sides).

Measured on gildegold 2f892529: 354 findings with the extent guess alone, 106 anchored, 81 with a majority, 39 with
the slot-keyed alignment, **32 in 20 functions** with the crossing test. Grades and gate unchanged. Read so far:
`gv_FireShots` +0xf5 / +0x108 (and the second copy at +0x191 / +0x1a2): the local at [esp+0x3c] goes to the vector's
+8 in ours and +4 in the original before `&vec` is passed: a y / z swap, a meaning difference. The rest is unread:
ai_CannonSwitchAnim, ai_FireCannon, ai_PlayerStatsPanel, ai_SendJobOrders, he_LabIncident, he_RunTrade,
ai_CalcMeisterRaeuber, ai_CalcMeisterWache, ai_CommandExecution, ai_DecideUseMeanObject, ai_FillNearRing,
ai_MasterLetterSettings, ai_UpgradeBuilding, cm_ExGebUpgrade, cm_RunTrial, gm_ForfeitEstate, hmt_CreateBinaryFile,
sv_CameraToObject, sv_FlyCameraToObject.

Still open from the task: the same rule in diffclass's slots class and in the prover's frame correspondence (a
verdict, not a report), once the warnings are read and the false positives known.
