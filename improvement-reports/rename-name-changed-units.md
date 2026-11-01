# rename: name the units whose objects changed

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** dcp rename
- **Problem:** `build: 42 of 43 unit(s) that read the renamed files keep their objects` does not say which unit changed, so the worker ran `dcp check` to find it.
- **Proposal:** name the unit, ideally also the functions whose bytes changed.
- **Repro:** `uv run dcp rename --from <file>` with ai_Unkf31140 / ai_Unka68d28 / ai_Unkf81220 / ai_Unk75e130 / unk_Unk51d2d0, at the parent of gildegold acf823a.
- **Cost of not having it:** about 1 minute.
- **Related:** rename-report-comment-rewrites.md
