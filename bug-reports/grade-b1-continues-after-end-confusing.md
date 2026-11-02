# B1 "the original continues after our end" names a range past the original's extent

- **Source:** match-base session 2026-11-02 (gildegold), worker 17
- **Severity:** minor
- **What happened:** `dcp grade sv_HandleRightClick` printed "the original continues after our end: 0x52e050..0x52e070 is no fill". The original function ends at 0x52e049 and the next function starts at 0x52e050. With ours at 1752 bytes vs 1801 (or 1794), the range seems to be our end mapped onto the original's addresses, so it reads as if the original were longer than its extent.
- **Expected:** give both ends, e.g. "ours ends +0x6d8, the original at +0x709 (0x52e049)".
- **Repro:** `uv run dcp grade sv_HandleRightClick` on an intermediate (shorter) version (gildegold before 0953094).
- **Impact:** ~5 minutes checking the extent with `dcp fn 0x52e050`.
- **Related:** grade-lost-address-comment-silent.md (same message in another situation)
