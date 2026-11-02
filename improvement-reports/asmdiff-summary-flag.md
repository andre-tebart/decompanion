# `dcp asmdiff --summary`: print only the `fn=` line

- **Source:** match-base session 2026-11-02 (gildegold), worker 69
- **Area:** `dcp asmdiff`
- **Problem:** with `--changed --regs auto` line 1 is the `fn=` header and line 2 the `legend:`; a variant loop doing `| head -2 | tail -1` printed the legend and lost the summary.
- **Proposal:** `--summary` printing only the `fn=` line (stable, script-friendly), for quick variant loops.
- **Repro:** `dcp asmdiff NAME --changed --regs auto | head -2 | tail -1` (gildegold 33968a7).
- **Cost of not having it:** one wasted round of 3 builds.
- **Related:** dcp-try-variants-in-memory.md
