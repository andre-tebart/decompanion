# Align on normalized keys

- **Priority:** P1 · **Size:** L · **Root:** R3

## Problem

- Repeated blocks pair one copy apart: ai_FillNearRing is one copy apart, and ai_CannonScene has its calls off by one.
  This is the residual after 87cebdd.
- `regs=none` is shown while diffclass shows a hunk-local eax<->ecx.
- After a layout shift, every branch is `!`.
- The reference check (refcheck.rs) reads the alignment's pairs. Reordered loads and stores whose texts are equal
  (`mov eax, dword ptr [X]`) pair crosswise and read as concrete reference differences when the prover cannot show
  the effects the same. On gildegold 05bbe07 that kept 8 shape functions at draft: ai_StepChapter4Step4,
  ai_TutorialMarkerUpdate (ai_Tutorial / ai_ClockMs loaded into swapped registers), he_Unk53f270, he_Unk53f370
  (ai_Time / +4), sv_FlyCameraToObject, sv_CameraToObject (sv_ViewPos / sv_ViewRot stores), ai_AimCannon
  (ai_CannonShot fields), ai_Unk4e30c0, d3if_SelectScene. With registers masked, each pairs with its own.
  They are declared debt in gildegold (15bda65): when this lands, lift them (`dcp promote`).

## Root cause

- The primary alignment (`difflib::opcodes` on `texts(la)` / `texts(lb)`, diffclass.rs:249, and asmdiff's
  `diff_lines`) runs on texts that still contain registers, stack slots and internal branch targets.
- Blocks that differ only in slots never match exactly, so Myers' shortest edit script can pair repeated copies one
  apart at equal cost.
- The register-masked alignment exists only for voting (`shape::voted_renaming`, shape.rs:569). It is global, so a
  renaming that holds in only one hunk loses the vote.

## Task

- Align with registers and stack offsets masked (`x86::shape_keys` / `mask_regs`).
- Map internal branch targets through the alignment before comparing: diffclass's branch check already does
  (`diffclass::Cuts`, the cut correspondence over the hunks); asmdiff's `!` on branches after a layout shift should
  read the same correspondence.
- Then classify each pair exactly; the per-hunk renaming falls out.
- This changes grade's distance and verdicts. Measure on gildegold as 87cebdd did, and keep the speed budget.

## Rejected

`--pair 0xA,0xB`, `--segments`, `--runs`, `--non-regs`.

## Model

§4: the alignment is part of the experiment, one per function; every reader of a pair reads it.

## Reports

- asmdiff-misaligns-repeated-cases (residual)
- asmdiff-regs-auto (residual)
- asmdiff-segments-and-runs
- diffclass-rotation-with-reorder-as-code (possibly)
