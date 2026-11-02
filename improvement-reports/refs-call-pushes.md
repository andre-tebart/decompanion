# `dcp refs`: show the original's pushes at each call site

- **Source:** match-base session 2026-11-02 (gildegold), worker 69
- **Area:** `dcp refs`
- **Problem:** f3gm's lead comment has an open "argument count differs" item for gm_Liking; the worker had to read disassembly to see the original pushes 3 arguments (`gm_Liking(id, j, 1)`).
- **Proposal:** `dcp refs NAME` lists, per original call site, the pushed argument count (and widths/values where known).
- **Repro:** `dcp refs gm_Liking` (gildegold 33968a7).
- **Cost of not having it:** a few minutes per callee with a disputed signature.
- **Related:** grade-call-arg-count-vs-definition.md, headers-signature-dry-run.md
