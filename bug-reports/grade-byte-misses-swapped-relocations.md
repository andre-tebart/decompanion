# `dcp grade` says byte while two relocations are swapped; only `dcp check` (M8) catches it

- **Source:** match-base session 2026-11-02 (gildegold), worker 56
- **Severity:** minor (an open M8 was committed once)
- **What happened:** in gm_IncomeKind4 (0x4fa2a0) the worker loaded `v1a4` and `v1a0` in the opposite order from the original. `dcp grade gm_IncomeKind4` said byte; `dcp check` reported M8 (relocation targets differ). The function was first committed with the open M8.
- **Expected:** `dcp grade` compares relocation targets (as M8 does) before calling a function byte, or at least prints the M8 line.
- **Repro:** swap two field loads with identical encodings but different relocation targets in a byte function; `dcp grade NAME` vs `dcp check` (gildegold, before 43c0db8).
- **Impact:** one commit with an open M8, a fix round.
- **Related:** asmdiff-reloc-vs-immediate-equal.md
