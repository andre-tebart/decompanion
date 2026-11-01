# `dcp refs` misses references made by `test byte ptr [mem], imm`

- **Source:** match-base session 2026-11-01 (gildegold)
- **Severity:** minor
- **What happened:** `dcp refs ai_Unkfd7f78` reported `refs_to=2`, both in `d3if_SelectScene`. It left out `rd_BuildRoad`'s `test byte ptr [0xfd7f78], 2` at 0x4bd309, although the source lines in the same output show it.
- **Repro:** `uv run dcp refs d3_Scene0Flags`, then compare with `uv run dcp disasm 0x4bcc20 | grep fd7f78`.
- **Impact:** small. The worker nearly concluded the datum had only one user unit.
