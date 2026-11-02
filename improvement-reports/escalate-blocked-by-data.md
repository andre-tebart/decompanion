# A "blocked by data" tag instead of escalating to deep

- **Source:** match-base session 2026-11-02 (gildegold), worker 18
- **Area:** `dcp escalate` / queues
- **Problem:** sv_OpenBook's only hunk comes from the `d3d_ZEnabled` view (see ../bug-reports/data-view-past-object-end-unflagged.md), a data/ownership question between d3_d3d and ts_texture. Escalating sent it to the deep queue, where no work on its own code can fix it.
- **Proposal:** `@blocked data:<symbol>` (or `dcp block NAME --on SYMBOL`) that drops it from the base queue and re-queues it once that datum is settled.
- **Cost of not having it:** small now; wasted deep-queue time later.
- **Related:** grade-readable-blocked-by-head.md
