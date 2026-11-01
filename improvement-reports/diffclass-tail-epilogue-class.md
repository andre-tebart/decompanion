# diffclass: a class for merged and duplicated return tails

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** diffclass, escalate
- **Problem:** in `rd_BuildRoad` the original keeps three identical `call d3sm_Destroy; …; ret` fail blocks, and our compile merges them into one (`push edx; jmp X`). In `d2_OpenForm` it is the other way round: the original shares the two `return -1` epilogues. Both show up as plain `code` hunks plus wrong branch targets, so they look like meaning differences.
- **Proposal:** a `tail`/`epilogue` class. It applies when one side jumps to a block that is instruction-identical (apart from registers) to a block the other side has inline. `escalate` should then accept the instruction-count gap without `--size-explained`.
- **Cost of not having it:** high. It took most of the time spent on `rd_BuildRoad`, including two experiments.

## Also seen (match-base session 2026-11-01 (gildegold), worker 4)
- **Cross-jumping of call sites, not just epilogues:** in ai_EvaluateProductionFlags, VC6 merged three `ai_SendJobOrders` call sites into one in ours where the original kept three. In ai_FindPartner the original has 7 epilogues, ours 3. diffclass reports both as large `code` hunks.
- **Proposal:** label it `crossjump` when one side has N similar call sequences and the other 1 plus `jmp`s, so workers can stop and escalate sooner.
- **Repro:** `uv run dcp diffclass ai_EvaluateProductionFlags` at gildegold commit d5c27ec, hunk at 0x480041.
- **Cost:** about 10 minutes trying source variants before escalating.
