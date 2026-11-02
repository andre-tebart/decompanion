# asmdiff marks jump-table references `!` even with `tables=equal`

- **Source:** match-base session 2026-11-01 (gildegold), worker 9
- **Severity:** minor
- **What happened:** with `tables=equal`, asmdiff still prints `! jmp dword ptr [edx*4 + $L16004] | jmp dword ptr [edx*4 + 0x4a9f24]` and the matching `mov dl, byte ptr [eax + $L16000]` index-table line.
- **Expected:** treat our local `$Lnnnn` table labels as equal to the original's table address when the tables compare equal.
- **Repro:** `uv run dcp asmdiff ai_CheckLeisureAction --symbols` (any switch with a jump table) at gildegold 7ef405a.
- **Impact:** small; noise that draws attention every time.
