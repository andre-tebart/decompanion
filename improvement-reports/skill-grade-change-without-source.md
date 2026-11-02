# Recording a grade change that needs no source change

- **Source:** match-base session 2026-11-02 (gildegold), worker 23
- **Area:** dcp-match-base skill / commits
- **Problem:** after the branch-check fix (decompanion 5469812) gv_BuryCharacter went draft -> shape with no source diff; the one-function-one-commit rule forced an `--allow-empty` commit.
- **Proposal:** a dcp command that records it (e.g. `dcp grade NAME --record`), or a skill line saying the wrap's grade list counts.
- **Cost of not having it:** ~1 minute plus hesitation.
