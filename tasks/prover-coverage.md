# Prover coverage instead of new diffclass classes

- **Priority:** P1 · **Size:** L (each step M) · **Root:** R10
- **Depends on:** prover-stop-reason-names-effects

## Problem

About 20 reports each ask for one more diffclass class or hint: address mode, rotation+order, slot permutation, spill,
arg-slot reuse, ivbias, induction base, moved block, prologue shrink-wrap, sched+copy, tail, commute, zero register,
duplicated test. Each one claims "same dataflow, other allocation, scheduling or layout".

## Root cause

- shape.rs and diffclass.rs explain one hunk at a time by text pattern, so any new pattern falls to `code`.
- Since 3b4d6a9, `equiv::prove` decides shape (grade.rs:139-156). Re-running on gildegold e3e3434 showed that most of
  the named functions now grade shape.
- What remains at draft is draft because the prover stops.

## Task

- Freeze the class set. It stays as a fast path and a navigation view.
- Tally the stop reasons over the corpus (`DCP_EQUIV_DUMP`), keep the mutant control at zero, and extend the prover in
  this order (by the sample):
  1. an escaped frame laid out otherwise;
  2. affine induction correspondences (x = a*y + c at loop heads), plus relocation binding with another addend
     (sym+0x48);
  3. the x87 stack carried across blocks;
  4. commuting stores to provably disjoint addresses within a block (a store never commutes with a call). A shape
     function whose named references cross is shape only with a proof (grade::code_grade): sv_CameraToObject,
     sv_FlyCameraToObject, ai_AimCannon, he_Unk53f270 on gildegold 05bbe07 wait on this (normalized-alignment
     pairs them right as well);
  5. one side's duplicated test or threaded jump (a block paired with a path);
  6. switch tables, flags across blocks, `rep scasb`.
- Test inputs: ls_ReadSceneRecords, sv_DrawNamePlates, gm_TakeOverCharacter, ai_TrustedOfTwo, gm_SpawnCharacter,
  lobby_Screen, gm_FreeStallCapacity, sv_UpdateGroundplan, ai_CannonExplosion.

## Rejected

Every new diffclass class.

## Model

A stronger object experiment: shape means the behaviour is equal for every layout (§8.5).

## Reports

- diffclass-address-mode-as-code
- diffclass-rotation-with-reorder-as-code
- diffclass-slot-permutation-per-hunk
- diffclass-regs-map-fixed-across-redefinition
- diffclass-frame-shift-indexed-as-code
- diffclass-ebp-frame-locals-as-code
- diffclass-arg-slot-reuse-class
- diffclass-spill-alloc-class
- diffclass-sched-and-regs-with-copy
- diffclass-tail-epilogue-class
- diffclass-moved-block-class
- diffclass-prologue-shrinkwrap-class
- diffclass-ivbias-class
- diffclass-induction-base-class
- diffclass-idiom-hints (commute, zero register, duplicated test)
- prover-downcount-loop-vs-end-compare
- skill-shape-vs-escalate-guidance (tool part)
