# An address one past an array's end is named after the next symbol

- **Source:** match-base session 2026-11-01 (gildegold)
- **Severity:** minor, but it has already led to wrong code
- **What happened:** the original's `cmp ecx, 0xfb91e4` was shown as `d3s_Lights+0x4`. It is really `&d2_Views[0x30].nwins`, the end of `d2_Views`. An earlier worker wrote `#define D2_VIEW_END_GUARD ((unsigned)&d3s_Lights + 0x4)` because of this name; it was fixed in gildegold commit a67e661.
- **Expected:** for an address at or just past the end of an array, show e.g. `d2_Views+0x81c4 (end of d2_Views)`, or both candidate names.
- **Repro:** before gildegold commit a67e661, `uv run dcp asmdiff d2_OpenForm --symbols`, line 0x47437a.
- **Impact:** about 10 minutes, plus a wrong fix in an earlier session.
