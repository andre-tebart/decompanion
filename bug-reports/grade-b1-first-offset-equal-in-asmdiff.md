# B1 "first at +0x27" points at an instruction asmdiff shows as equal

- **Source:** match-base session 2026-11-01 (gildegold), worker 13
- **Severity:** minor
- **What happened:** for sv_OpenBuildingPanel, `dcp grade` reported `B1 byte: 136 of 784 bytes differ, the first at +0x27`, but `dcp asmdiff` showed the first 183 instructions as equal; probably a relocation or immediate both sides print the same.
- **Expected:** B1 names the instruction at that offset (and both byte sequences), or asmdiff marks byte-only differences.
- **Repro:** `uv run dcp grade sv_OpenBuildingPanel` vs `uv run dcp asmdiff sv_OpenBuildingPanel` at gildegold baa6b2c.
- **Impact:** small; made the worker doubt the alignment.

## Also seen (match-base session 2026-11-02 (gildegold), worker 19)
- sv_UpdateQuickChat at shape: `dcp grade` says `B1 byte: 2 of 160 bytes differ, the first at +0x5d`, but `dcp asmdiff` shows `... 42 equal instructions ...` and `dcp diffclass` says `hunks=0 ... verdict=shape summary: identical instructions`. The two bytes are `je rel8` targets (ours to the final `ret`, original to a mid-function `ret`); before shape asmdiff showed them as `!`. Proposal: asmdiff/diffclass keep listing differing branch targets whenever B1 reports bytes, and grade summarises the residue (`B1: branch targets only` / `B1: order only`) so it's clear no meaning fix is left. Cost: ~3 minutes.
