# The tie-break sampler: is it the declaration set or the text?

- **Priority:** P0 · **Size:** M · **Replaces:** tiebreak-probe-positions

## Problem

A function whose only difference left is allocation (regs / slots / order, the prover equal) can be held there by
its own text (another spelling) or by the declaration set its unit sees (a VC6 tie-break). A worker cannot tell the
two apart, and a fixed probe family (four typedef sets before the unit) cannot prove that a function is not held by
the declaration set: it misses changes inside the include chain and inside type definitions.

## Done (2026-11-09)

`dcp headers sample NAME [--n 32] [--seed 1] [--dry-run]` (tiebreak.rs, the sampler):

- The unit preprocessed once (CL /E); a control compile of the expanded text must give the build's grade.
- n samples, each 1..3 changes before the function: an unused typedef / struct tag / prototype / extern at a random
  file-scope place of the include chain (every line keeping its number by a `#line` after it), or (one in three) a
  layout-preserving member change: a padding array (`char pad..[N]`) split in two or wrapped in a struct of its
  own, a union given a one-byte member. A sample that does not compile is dropped.
- The function's code is compared across samples (masked fields, numbered names by kind): sensitive when it moves;
  the best grade over the samples is its source-proven grade. The record goes to ledger/tiebreak.tsv (an earlier
  better grade kept), so the queues count a proven byte as done.
- `dcp grade NAME` prints a `tiebreak:` line (sensitive / insensitive by the sampler / insensitive under the four
  probes only / not measured); `dcp escalate` appends the state to the reason. match-base's escalation section
  says when to sample and what each answer means.
- About 2 s for 32 samples of a gildegold unit (8 cores); 6 s for 256.

## Measured

gildegold 8941d6a9: ai_TutorialInitChapter2 sensitive (2 codegens; 68 of 128 samples give byte: proven byte);
pool_Next and d3_CloneObject insensitive in 128 / 256 samples; ai_Unk483a60 (recorded sensitive after an AIBLD
member was typed) insensitive now, and a hand-made AIBLD padding wrap moved only ai_TutorialInitChapter2: the old
sensitivities are gone with the headers since.

Every shape-level deep item (risk shape / proved: 564 functions, 32 samples each, about 15 minutes): **562
insensitive**, 2 sensitive: gm_RefreshGoodsLists (2 codegens, none better than shape) and ai_TutorialInitChapter3
(its preprocessed control already gives shape where the build gives draft; 11 codegens, best shape). For almost every
deep item the residue is in the function's text. A control that differs from the build is now a codegen of its own
and proof of sensitivity (or a stale build), not an error.

## Left

- Bias member changes towards the types the function's text names (coverage: the members of all headers are
  sampled uniformly now).
- The unit-level declaration pass (a set under which every sensitive function of the unit is byte at once).
