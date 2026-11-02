# Prover: treat a down-counted loop and an end-compare loop with the same trip count as equal

- **Source:** match-base session 2026-11-02 (gildegold), worker 69
- **Area:** shape prover / `dcp diffclass`
- **Problem:** in gm_TakeOverCharacter (0x5064d0) the proof stops with `proof: unknown: the branches test different conditions` at a loop exit: the original counts `ebx = 0x100` down with `dec ebx / jne`, ours compares the derived offset `cmp edi, 0xa900 / jb`. Same trip count; three source variants (int i, unsigned i, byte-offset spelling) did not change the compiler's choice.
- **Proposal:** recognise this induction-variable equivalence (counter n down to 0 vs base + k*stride up to base + n*stride) so the proof continues past the loop exit.
- **Repro:** `dcp diffclass gm_TakeOverCharacter`; proof stops at ours +0x79 / original +0x7e (gildegold 33968a7).
- **Cost of not having it:** 3 rebuild variants; contributed to escalating the function to deep.
- **Related:** diffclass-ivbias-class.md, diffclass-induction-base-class.md
