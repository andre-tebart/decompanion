# `asmdiff --changed`: show only differing lines with context

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** asmdiff
- **Problem:** the worker piped `dcp asmdiff` through `grep -v equal` most of the time.
- **Proposal:** `--changed`, which shows only differing lines plus a few lines of context.
- **Cost of not having it:** context only.
