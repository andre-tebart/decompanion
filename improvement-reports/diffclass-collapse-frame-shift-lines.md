# `dcp diffclass`: collapse frame-shift hunks into one line

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Area:** `dcp diffclass` (output size)
- **Problem:** ai_CabinetSpyByMoney printed 20-30 lines like `0x00581c99 frame 2 stack offsets shifted by 0x4`; the header line already says the frame differs by 4.
- **Proposal:** one line per contiguous shift, e.g. `frame: 36 lines shifted by 0x4 (0x581c06..0x581da2)`; full list behind `--all`.
- **Cost of not having it:** context only.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 51)
- `dcp diffclass ai_GypsyHelperWindow` printed ~100 lines (acceptable). A `--summary` mode with one line per hunk (address, class, count, first differing instruction) would cover the triage pass.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- `dcp diffclass gm_DailyCharacterStep --all`: ~250 lines, ~45 of them "frame 2 stack offsets shifted by 0x4". Want `frame-only hunks: 45 (offsets +0x4)`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- `dcp diffclass gm_MayTakeJob`: ~150 lines; the branch-target list appears both at the top and again in the summary line. Print it once; summary gives counts only.
