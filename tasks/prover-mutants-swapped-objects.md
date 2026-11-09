# Prover mutants: swapped objects, offsets and constants

- **Priority:** P0 · **Size:** S · **Related:** prover-coverage (its mutant control)

## Problem

Since 3b4d6a9 a proof can raise a function whose named references cross (grade::code_grade: `named_differs() ||
proved`). That is right for reordered code, but it makes the prover's soundness part of every M8 verdict. The mutant
control in prover-coverage keeps the false-proof rate at zero for the mutants it has, but not for the bug classes
gildegold actually had: two neighbouring globals of one type swapped (`dd_Width` / `dd_Height`, `qnt_PalG` /
`qnt_PalB`), a record field one slot off, a local array index, a constant spelled as an address.

## Task

- Mutants over gildegold's byte-matched corpus (DCP_EQUIV_DUMP): in our bound code, at one site, replace a datum's
  address with its φ neighbour's (the next object of the same size), a field displacement with ±4, a stack
  displacement with ±4 inside one local, an immediate with another. Every mutant must fail to prove (and must not
  prove under census either).
- Fails the corpus test on any proved mutant, with the mutant named.

## Reports

- this task came from a review of gildegold's deep queue (2026-11-09), not from a report

## First run (2026-11-09, gildegold f19a0510, 562 shape functions dumped, 312 proved)

`mutants: 312 functions, 34913 mutants, 80 proved equal`. Most of the 80 are the known class (a dead stack slot,
`[esp+X]` stores of arguments never read). The new mutants found these, each still to be decided (a change the
code cannot see, or a prover hole):

- `gm_BuildingSkill` 0x50937f / 0x509385: `fmul qword [0xF006E900]` (an **unbound** placeholder address) and
  `fadd qword [0x5EB7E8]`. disp +4, disp -4 and the two swapped all prove equal. Suspect: how the prover pairs an
  unbound placeholder address (a wildcard that pairs with whatever the original loads?). If so, any unbound
  reference is unchecked in a proof.
- `gv_RankCulprits` 0x4f3cbd and `gv_RankCulpritsAll` 0x4f3e45: `lea eax, [eax*4+0x770B80]` +4 and -4 prove equal
  (an address that is computed and then never used for its value?).
- Swapped absolute addresses that prove equal: `ai_WoodKontorContact` 0x623898 <-> 0x5fe710, `cm_DrawScrollArrows`
  0x5fe708 <-> 0x5edc50, `sv_UpdateSkyPhase` 0x760548 <-> 0x76054c. Probably the two operands of a commutative
  fmul / fadd (then equal for real), to be checked one by one with DCP_EQUIV_ONLY / DCP_EQUIV_AT.

Reproduce: start the daemon with DCP_EQUIV_DUMP=DIR, `dcp asmdiff NAME` per function, then
`DCP_EQUIV_CORPUS=DIR cargo test --profile iter --lib equiv::tests::mutants -- --ignored --nocapture`.
