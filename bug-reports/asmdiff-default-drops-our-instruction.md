# Default `dcp asmdiff` view drops one of our instructions that `--plain` shows

- **Source:** match-base session 2026-11-02 (gildegold), worker 60
- **Severity:** minor (diff looks smaller than it is)
- **What happened:** on `dcp asmdiff gm_SetTime` (0x4fe1e0, draft stage) the default view showed the original's first instruction (`+ mov ecx, [esp+0x10]`) but no `-` line for ours; `--plain` showed `- 0x004fe1e0 movzx cx, byte ptr [esp + 8]`.
- **Expected:** every instruction of both sides appears (as `-`/`+`/`!`/`=` or inside a counted equal run).
- **Repro:** give gm_SetTime its old body (hour, sec & 0xff, min & 0xff), compare `dcp asmdiff gm_SetTime` with `--plain` (gildegold, before b6d1679).
- **Impact:** small; noticed only because the instruction counts did not add up.
