# asmdiff --symbols names a jump inside our own function after another function's symbol

- **Source:** match-base session 2026-11-02 (gildegold), worker 19
- **Severity:** minor
- **What happened:** on sv_PopTo (ours 50 bytes vs original 38) asmdiff printed `!  0x0052fb5b  jl sv_PumpMessages | jl 0x52fb75`: our jump to our own `pop esi; ret` was named after the symbol at that address in the original's layout, reading like a tail call.
- **Expected:** a jump staying inside our function is shown as `fn+0xNN` (our own offset), never as another function's symbol.
- **Repro:** `git checkout 92add7d -- src/sv.c`, `uv run dcp build`, `uv run dcp asmdiff sv_PopTo --symbols` (gildegold).
- **Impact:** ~2 minutes checking whether the draft called sv_PumpMessages.
- **Related:** asmdiff-symbols-wrong-library-callee.md
