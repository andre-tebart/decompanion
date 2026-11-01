# asmdiff views for big functions: `--segments` and `--runs`

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** asmdiff
- **Problem:** on big functions (d3fl_Draw has 2800 instructions; PrepareWater and txt_Format are similar) the worker wrote throwaway scripts for two views:
  - **Segments:** split the asmdiff at `call` / `fistp` anchors and compare ours/original counts per segment. This was the fastest way to find missing or extra statement groups; d3fl_Draw at cb2e91b showed edge blocks at -13 / -19 / -5 / -7 only after segmenting.
  - **Runs:** find runs of 8 or more consecutive `+`-only or `-`-only lines. These pointed straight at layout or structure differences: the out-of-line blocks in ai_FindPartner and ai_EvaluateProductionFlags, and the flags-0x10 order in the job-order loop.
- **Proposal:** `dcp asmdiff NAME --segments [--anchor call|fistp|ret]` and `dcp asmdiff NAME --runs N`.
- **Cost of not having it:** about 15 minutes for the segment script and about 5 for the runs script.
