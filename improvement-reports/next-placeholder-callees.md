# `dcp next`: list the callees that are still placeholders

- **Source:** match-base session 2026-11-02 (gildegold), worker 46
- **Area:** `dcp next`, match-base skill
- **Problem:** Q2 on a caller (ai_AlchemistWindow) stayed open because its callees (`ai_Unk57dc50`, ...) were placeholders without evidence of their own yet. The worker found that out only from `dcp grade` after renaming the function, then made reasoned-guess renames.
- **Proposal:** the `dcp next` item line adds `callees_placeholder=ai_Unk57dc50,...`; the skill says whether a reasoned-guess rename of a callee is acceptable and how to word its `--why` ("reasoned guess: called from X to ...").
- **Cost of not having it:** a few calls; uncertainty about guess renames. Related: grade-q2-full-list.md
