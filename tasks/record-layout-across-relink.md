# Record layout across the relink: fields of one record must keep their distances

- **Priority:** P0 · **Size:** S-M · **Done:** 2026-11-09

## Problem

From bug-reports/split-record-table-scaled-index-not-caught.md (gildegold tutorial crash, fixed in d1633d50): the
scene-kind table at 0x92c500 (12 records of 0x14 bytes) was declared as five symbols (`cm_KindRun[1]`, ...,
`cm_KindCheck[60]`) indexed `[kind*5]` / `[kind*20]`. The code matched byte for byte and every reference agreed with
φ, since both hold at the original's layout. The relink put cm_KindCheck 0x14 after cm_KindRun instead of 0x10, and
every kind's check read the next kind's run: a crash in normal play.

## Done

layoutcheck.rs, run after every successful link (`dcp link`, `dcp check`):

- From our objects: within a straight run of code, the relocated displacements of memory operands with a register in
  the address, per (base, index, scale), until an instruction writes one of those registers. Two or more named data
  objects through one expression are fields of one record.
- A pair is a record's when its objects lie at most 0x100 apart in the original, or one of them is declared as a
  single element. That leaves out parallel arrays indexed alike (txt_Ptrs[i] / txt_Random[i]) and buffers
  addressed through one computed offset, which lie whole objects apart.
- Our link map's distance must equal φ's; otherwise `M.layout: <fn> addresses A and B through one register
  expression [eax + X]: the original keeps B at A+0x10, our link at A+0x14 ...`, and the gate fails
  (`link:layout=N`): the image links, but it does not run as the original does.

## Measured

gildegold d1633d50~1: exactly the crash (cm_RegisterSceneKind: cm_KindRun / cm_KindCheck), gate FAIL. d1633d50
(the fix): nothing, gate ok. Before the record-span rule there were 18 groups, 17 of them parallel arrays or buffers.

## Left (from the report)

- The index's range against a declared size (`sym[i*5]` past N) as its own finding: the layout check covers the
  case that breaks at run time, not a table our link happens to lay out right.
- Suggest the struct (the group's fields, their offsets, the stride) in the line.
