# `dcp session wrap`: say why an untouched function's grade changed

- **Source:** match-base session 2026-11-02 (gildegold), worker 46
- **Area:** `dcp session wrap`
- **Problem:** the wrap listed `ai_TutorialInitChapter2 shape -> byte` though the worker never edited it; the cause was the gap-data move of ai_ShotTable / ai_ShotDirty (typing commit before the wrap). Correct, but the worker had to work out the cause.
- **Proposal:** for a function whose source did not change, add `cause=` to its `grades changed` line: the data / header / declaration change in its unit that moved it (e.g. `cause=data ai_ShotTable`).
- **Repro:** gildegold 80c1371 wrap report.
- **Cost of not having it:** low. Related: skill-grade-change-without-source.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 69)
- Wrap listed `0x00579570 unk_575860 ai_TutorialInitChapter3: draft+readable deep -> shape+readable deep`; src/unk_575860.c had no commit this session, but it includes f3gm.h and gv.h, both edited (new prototypes; ORDCHAR union at +0x30, fields at +0x50/+0x194). `dcp grade` now says B2 shape, proved (86 block pairs), size 5377 vs 5377. Cannot tell a real gain from a prover/classifier change. Proposal addition: tag causes "recompiled via include X" / "rule/prover version changed" and flag changes in units outside the session's commits. Repro: wrap at gildegold 33968a7.

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- After ORDCHAR edits in gv.h the wrap listed ~10 improved functions in other units (f3init, he, unk_58bbd0, d3_*); a "changed by header X" attribution would make these tie-break moves auditable. Wrap at gildegold befd916.
