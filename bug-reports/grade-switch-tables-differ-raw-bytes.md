# "switch tables differ" is reported as raw bytes instead of table entries

- **Source:** match-base session 2026-11-02 (gildegold), worker 67
- **Severity:** minor (misleading)
- **What happened:** `dcp grade gm_TitleGroup` (0x504ad0) gave `switch tables differ (12): byte +0x44: 0x00 vs 0x48; byte +0x45: 0x01 vs 0x4b; ...`. The cause: ours had 17 jump-table entries and the original 18; case 0 had its own entry (pointing at the exit) in the original, while ours folded it into the default.
- **Expected:** an entry-level summary, e.g. `jump table: ours 17 entries, original 18; original entry 0 (case 0) -> exit, ours folds case 0 into default`, plus index-table values per case.
- **Repro:** `dcp grade gm_TitleGroup` on its draft (gildegold, before 96ddc48).
- **Impact:** both tables dumped and decoded by hand, plus 4 build tries.
- **Related:** disasm-decodes-jump-tables.md, ../improvement-reports/diffclass-switch-case-order.md
