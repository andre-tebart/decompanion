# diffclass: an `ivbias` class for induction-variable displacement bias

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** diffclass
- **Problem:** in `ls_WritePlayerSlots` / `ls_ReadPlayerSlots` every displacement in the record loop is shifted by one constant against one base register (`add edi,0x14` vs `add edi,0x18`, `[edi-4]` vs `[edi-8]` ...). diffclass shows `code` hunks, so the functions can only be escalated with a long hand-written reason.
- **Proposal:** an `ivbias` class (same instructions, one base register, constant displacement delta within one loop). It would also tell the deep queue exactly what to try. Hint from the session: `ls_ReadStatistics` byte-matched once written as a plain index loop; the escalated `ls_WriteStatistics` may fall to the same rewrite.
- **Repro:** `uv run dcp diffclass ls_WritePlayerSlots` at gildegold 635eba0.
- **Cost of not having it:** about 10 minutes on four source variants that could not change it; also produces false branch notes (bug-reports/grade-branch-targets-differ-same-target.md).
- **Related:** vc6-optimizer-hints.md
