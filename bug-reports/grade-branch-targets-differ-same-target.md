# grade/diffclass report "branch targets differ" when both targets are the same

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Severity:** minor
- **What happened:** `dcp grade` (and the B3 line it shares with `diffclass`) lists a branch difference with identical targets: `branch targets differ (1): jl at +0x1bb: ours to +0xa1, the original's to +0xa1`. Same on `ls_ReadPlayerSlots`: `jl at +0x1cc: ours to +0xaf, the original's to +0xaf`. The real difference in that loop is a 4-byte record-pointer bias (see improvement-reports/diffclass-ivbias-class.md). Worker's guess: the check compares the raw displacement or a pre-alignment target.
- **Expected:** report a branch only when the aligned targets differ, or say why (e.g. "displacement differs, same target").
- **Repro:** `uv run dcp grade ls_WritePlayerSlots` at gildegold commit 635eba0; `uv run dcp grade ls_ReadPlayerSlots` at 6292ee1.
- **Impact:** about 5 minutes ruling out a hidden control-flow difference; noise in the escalation reason.
