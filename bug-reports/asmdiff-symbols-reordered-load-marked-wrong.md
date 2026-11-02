# asmdiff --symbols marks `!` (wrong datum) when only the load order of a struct copy differs

- **Source:** match-base session 2026-11-01 (gildegold), worker 9
- **Severity:** minor
- **What happened:** in aip_ExecPamphlet and aip_ExecAnschwaerzen, `asmdiff --symbols` showed `! mov edx, dword ptr [ai_Time+0x4] | mov edx, dword ptr [NOWX]`. Both sides copy the same 14-byte AITIME; the alignment paired loads from different addresses because they are scheduled differently. The ledger names (`NOWX`, `ai_TimeHour`, `0x770ae8`) don't read as `ai_Time+N`, which made it look like a wrong field.
- **Expected:** print the raw address next to the name on `!` lines (`[ai_Time+0x4 =0x770ae4] | [NOWX =0x770ae0]`), and/or when the set of addresses a hunk reads is the same on both sides, mark it reordered instead of `!`.
- **Repro:** `uv run dcp asmdiff aip_ExecPamphlet --symbols` on the pre-session draft (gildegold 7ae5254).
- **Impact:** 3-4 minutes checking for a wrong datum.
- **Related:** asmdiff-symbols-wrong-library-callee.md, asmdiff-symbols-image-base-immediate.md
