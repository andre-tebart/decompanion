# `dcp disasm` decodes jump/index tables as instructions

- **Source:** match-base session 2026-11-02 (gildegold), worker 66
- **Severity:** minor
- **What happened:** `dcp disasm 0x503fa0` prints the table at 0x504010 as junk code (`call 0xf4509054`, `aas`, ...), while `dcp dump` labels the same bytes `jumptable@` / `idxtable@`.
- **Expected:** disasm stops at the table and prints its entries (targets for jump tables, indices for index tables).
- **Repro:** `dcp disasm 0x503fa0` (gm_BuildingTypeOfJob) at gildegold f30e72e.
- **Impact:** ~4 dump calls and decoding index tables by hand for gm_PermissionBits, gm_SexForTitle, gm_BuildingTypeOfJob and gm_JobSlots.
- **Related:** asmdiff-jumptable-label-marked-differ.md, ../improvement-reports/diffclass-switch-case-order.md
