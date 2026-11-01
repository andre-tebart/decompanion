# `dcp grade`: show the instruction counts and the escalate size threshold

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** dcp grade / dcp escalate
- **Problem:** escalate's size gate uses asmdiff's `ours=/original=` instruction counts, but `dcp grade` reports `size N vs M` in bytes. The worker ran asmdiff only to check whether escalate would refuse.
- **Proposal:** add `ins=ours/original` and the escalate threshold (`max(12, 1%)`) to the grade line.
- **Repro:** `uv run dcp grade ai_FindPartner` against `uv run dcp asmdiff ai_FindPartner | head -1`.
- **Cost of not having it:** one extra command per function.
