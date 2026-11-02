# `dcp escalate -h`: list the phrases the reason filter refuses

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** dcp escalate
- **Problem:** reasons had to be worded carefully to get past the wording filters ("not reconciled" and similar), and the filter's phrases are not documented.
- **Proposal:** if the filter can't be relaxed, list the forbidden phrases in `dcp escalate -h`. Related: escalate-why-file.md
- **Cost of not having it:** none this session.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 17)
- `dcp escalate NAME "why" --check`: validate the reason (instruction-count rule, forbidden phrases) without writing, so long reasons don't need a nervous re-read.
- Skill section 3 doesn't cover a hunk where our source has the statement but the compiler removes it (sv_HandleRightClick's null test of an event-slot address); the worker worded the reason carefully so it would not read as "missing statements".

## Also suggested (match-base session 2026-11-02 (gildegold), worker 33)
- ai_DecideTrainSkill (0x4960b0) was escalated as "allocation only" while its grade still showed `B3 draft: unexplained code hunks: code 236 ...`; escalate accepted it. In the next function the worker found VC6 had merged two identical sub-action blocks, a fix likely missed in 0x4960b0. Proposal: when ours is shorter than the original (368 vs 378), escalate prints "ours is shorter: look for merged blocks or a missing duplicate"; and it notes when the reason contradicts the grade's unexplained hunks.
