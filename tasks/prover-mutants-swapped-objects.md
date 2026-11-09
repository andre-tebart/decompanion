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
