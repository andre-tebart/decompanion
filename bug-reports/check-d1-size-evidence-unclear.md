# D1 "the object gives it N+4 bytes" doesn't say where the larger size comes from

- **Source:** match-base session 2026-11-02 (gildegold), worker 55
- **Severity:** minor
- **What happened:** after moving `AIBOOKMARK ai_Bookmarks[11]` (exactly 132 bytes) out of the gap block, `dcp why 0x6f5ec0` showed `D1 ... the object gives it 136 bytes, the symbol at 0x6f5f44 leaves 132; fine if the last 4 are alignment padding`. Nothing says where 136 comes from (possibly the original's loop-end pointer 0x6f5f48). Same for `int ai_ScreenshotCount` (0x6f2674): "gives it 8 bytes".
- **Expected:** name the evidence for the larger size (site address, or "next definition of this unit at ..."), and say whether this is a new D1 or a strict-only one.
- **Repro:** `dcp why 0x6f5ec0` at gildegold 65f9a10.
- **Impact:** couldn't tell if it was the new D1 the skill forbids; stash, rebuild, count D1 lines, restore: ~4 calls and two full builds.
- **Related:** check-d1-stale-extent-after-split.md, check-d7-size-message-unclear.md
