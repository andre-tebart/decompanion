# `dcp grade`: show the instruction counts and the escalate size threshold

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** dcp grade / dcp escalate
- **Problem:** escalate's size gate uses asmdiff's `ours=/original=` instruction counts, but `dcp grade` reports `size N vs M` in bytes. The worker ran asmdiff only to check whether escalate would refuse.
- **Proposal:** add `ins=ours/original` and the escalate threshold (`max(12, 1%)`) to the grade line.
- **Repro:** `uv run dcp grade ai_FindPartner` against `uv run dcp asmdiff ai_FindPartner | head -1`.
- **Cost of not having it:** one extra command per function.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 5)
- `ours=` / `original=` from the asmdiff head was the quickest sign of missing statements, and it decides whether `dcp escalate` is allowed; having it on the grade line would save an asmdiff call per round.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 9)
- Also on the `dcp next` item line (`ins=ours/original`), not only `dcp grade`. One extra command per function otherwise.

## Also seen (match-base session 2026-11-02 (gildegold), worker 30)
- ai_DecideBuildSculpture: ours=193 vs original=181, a difference of exactly 12. The skill says escalate refuses only above max(12, 1%), but the boundary was unclear, so the worker passed `--size-explained`. Proposal: escalate (or grade) prints the computed limit, e.g. "diff 12, limit 12: ok".
