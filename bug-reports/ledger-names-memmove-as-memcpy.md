# The ledger names 0x5df710 `memcpy`, so every `memmove` call gets a false `!`

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Severity:** minor (misleading output; invites wrong "fixes")
- **What happened:** asmdiff shows `! call memmove | call memcpy` at every overlapping-copy call. VC6 /O2 inlines memcpy as an intrinsic (`rep movsd/movsb`), so a real call to 0x5df710 can only be `memmove`. memcpy.obj and memmove.obj in libc have identical bytes, which probably let the signature match pick the wrong name.
- **Expected:** name 0x5df710 `memmove` in the ledger. Failing that, suppress `!` for a pair of library names that share one body.
- **Repro:**
  - `uv run dcp asmdiff txt_Format --symbols | grep memmove` (gildegold commit 97c857c)
  - `uv run dcp asmdiff d3fl_PrepareWater --symbols | grep memcpy` (commit 429e36b, at 0x441118)
  - `uv run dcp why 0x5df710` shows the name.
- **Impact:** about 5 minutes per function, in 3 functions.
