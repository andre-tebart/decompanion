# asmdiff --symbols prints the immediate 0x400000 (image base) as a symbol and marks it differing

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Severity:** minor
- **What happened:** `! mov dword ptr [d3anim_CacheMax], X | mov dword ptr [d3anim_CacheMax], 0x400000`. Ours is `#define ANIM_CACHE_BYTES 0x400000`, a plain immediate; the function later byte-matched with that line unchanged, so it is display only. Probably an immediate equal to the image base resolves to an image/base symbol.
- **Expected:** a bare immediate without a relocation is never shown as a symbol and never marked `!`.
- **Repro:** in gildegold, `git checkout acf823a -- src/main.c` (main_OpenEngine before its fix), then `uv run dcp asmdiff main_OpenEngine --symbols`.
- **Impact:** about 5 minutes checking whether the constant was a const global loaded from memory.
