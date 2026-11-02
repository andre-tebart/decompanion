# `dcp dump` labels unknown data at unaligned offsets inside an int table

- **Source:** match-base session 2026-11-02 (gildegold), worker 29
- **Severity:** minor
- **What happened:** `dcp dump 0x5ee0f8 0x30` annotated `unknown.data@0x5ee111 unknown.data@0x5ee115` inside an int table. gv_RankWorth is declared at 0x5ee0f8 with 7 ints, but gv_CheckRankUp reads 11; the last 4 lie under `hmt_Unk5ee114`. The worker expected a label at 0x5ee114.
- **Expected:** labels at the referenced/aligned addresses (or explain where 0x...11 / 0x...15 come from).
- **Repro:** `uv run dcp dump 0x5ee0f8 0x30` at gildegold 3209111.
- **Impact:** confusion while diagnosing the table size (left as an `Open:` line in gv.c).
- **Related:** ../improvement-reports/data-split-object-by-access.md
