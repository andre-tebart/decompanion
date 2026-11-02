# asmdiff: `-` = ours / `+` = original is easy to misread

- **Source:** match-base session 2026-11-02 (gildegold), worker 59
- **Area:** `dcp asmdiff`
- **Problem:** `-` is ours and `+` the original, the opposite of how a patch from ours to the target reads to most people. The worker misread one hunk (the float compare form in gm_PopulationStep) and redid it.
- **Proposal:** an `ours` / `orig` tag on each differing line, or an option to swap the sides.
- **Cost of not having it:** one redone hunk.
