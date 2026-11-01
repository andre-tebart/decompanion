# asmdiff `--symbols` marks `!` when both sides are the same address under different names

- **Source:** match-base session 2026-11-01 (gildegold)
- **Severity:** minor (misleading output)
- **What happened:** `!` ("wrong callee, datum or string") was shown on lines where both sides resolve to the same address and only the name differs:
  - `d3_DefaultScene` vs `ai_Unk5fb5b0`
  - `txt_Ptrs` vs `d2_Strings`
  - `_real` vs `ai_Unk5eb788`
  - `??_C@_00A@` vs `ch_EmptyName`
  - `rd_Road+0x10` vs the bare `0xf81310`
- **Expected:** suppress `!` when both sides resolve to the same address, or use a separate mark (e.g. `=`) for "alias / unnamed on one side".
- **Repro:** `uv run dcp asmdiff d2_OpenForm --symbols`
- **Impact:** about 5–10 minutes per session spent running `dcp why` to rule out real errors.

## Also seen (match-base session 2026-11-01 (gildegold), worker 4)
- **Two source names declared at one address**, not just `+offset` fields, give a `!` on every use:
  - `d3fl_DetailScale` / `ai_Unk633748` at 0x633748 (f3init.c defines `ai_Unk633748`; d3_fl.h declares the extern `d3fl_DetailScale`)
  - `d3_Unk633b1c` / `d3if_Dir` / `d3o_Dir` at 0x633b1c
  - `d3_Time` / `ai_ClockMs`
  - `ai_Watch` / `ai_Unkf895a0`
  - `d3_SortMax` vs `d3_Cfg+0x18`
- **Proposal:** a lint/check rule that flags two different source names at one address (a naming conflict), in addition to not firing `!` when both sides resolve to the same address.
- **Repro:** `uv run dcp why 0x633748`; `uv run dcp asmdiff d3fl_MakeJitter --symbols | head -8` (commit f61db4d); `uv run dcp refs d3_Unk633b1c`.
- **Impact:** about 5 minutes. It also blocked a Q2 rename of `d3_Unk633b1c`, because it was unclear which name was meant.
