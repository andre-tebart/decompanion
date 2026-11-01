# A scoped edit for one function's body

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** dcp fn
- **Problem:** a scripted string replace on `float dx, dz, ex, ez;` also changed `rd_FillQuad`, which broke the build.
- **Proposal:** `dcp fn NAME --write FILE` (replace the body at the `at=` lines) and/or `dcp fn NAME --print-body`, so edits stay inside the function's line range.
- **Cost of not having it:** about 3 minutes.
