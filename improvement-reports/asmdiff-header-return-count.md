# Show a count of `return` epilogues in the asmdiff header

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** asmdiff
- **Proposal:** add something like `returns ours=2 original=5` next to the frame line. It points straight to duplicated or merged epilogues (see diffclass-tail-epilogue-class.md).
- **Cost of not having it:** none directly; it would have pointed to the cause in `rd_BuildRoad` sooner.
