# `dcp grade`: locate a size difference when the instruction counts agree

- **Source:** match-base session 2026-11-02 (gildegold), worker 56
- **Area:** `dcp grade` / `dcp asmdiff`
- **Problem:** gm_CharacterWages (0x4fa700): `size 682 vs 681` with 207 = 207 instructions. All branch targets at the end were off by one byte, but no tool showed which instruction was encoded one byte longer.
- **Proposal:** a line like `size: first shift at +0x..: ours <ins> (N bytes) vs <ins> (M bytes)`.
- **Cost of not having it:** 3-4 calls that found nothing.
- **Related:** grade-show-instruction-counts.md, ../bug-reports/grade-branch-shift-noise.md
