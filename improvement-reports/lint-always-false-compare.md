# lint: flag compares that are always false (constant out of type range)

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** dcp lint / check
- **Problem:** `ai_PlayerId == -1` with `unsigned short ai_PlayerId` compiled silently and is never true; the original compares with 0xffff (`cmp cx, 0xffff`). A typical Ghidra-draft meaning bug.
- **Proposal:** report clang's `-Wtautological-constant-out-of-range-compare` (or equivalent) as a meaning warning.
- **Repro:** `ls_WriteSaveHeader` (0x5194c0) before gildegold d7d3f26.
- **Cost of not having it:** about 2 minutes, found by reading the asm; cheap to automate.
- **Related:** diffclass-idiom-hints.md (char compare that can never be true)
