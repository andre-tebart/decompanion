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

## Second run, after the fix (2026-11-09)

The `gm_BuildingSkill` cases were a hole: a tail jump (`jmp _ftol`) compared registers and stack arguments but not
the FPU stack, which is `_ftol`'s argument, so any float operand before it went unchecked. Fixed in equiv.rs (the
tail jump compares the FPU stack; test a_tail_call_compares_the_fpu_stack). On the corpus, one proof is lost
(gm_BuildingSkill: unknown); `mutants: 311 functions, 34872 mutants, 73 proved equal`. All new-class survivors
were read and are equal for real:

- swaps: `ai_WoodKontorContact` (the two loads of one `cmp ecx, eax; jne`), `cm_DrawScrollArrows` (the operands of
  one `fmul`), `sv_UpdateSkyPhase` (the operands of one `add edx, ecx`): commutative;
- `gv_RankCulprits` / `gv_RankCulpritsAll`: `lea eax, [ai_Chars + eax*4]` is dead (eax is overwritten by the call's
  result or by `lea eax, [esp+0x1c]` on every path).

Left: the known class (stack stores never read). A commutation-aware swap mutant (skip pairs that feed one
commutative operation) would make the control silent; not needed while the survivors are few enough to read.
