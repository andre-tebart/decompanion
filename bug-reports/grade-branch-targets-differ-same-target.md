# grade/diffclass report "branch targets differ" when both targets are the same

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Severity:** critical (fixed in decompanion 5469812)
- **What happened:** `dcp grade` (and the B3 line it shares with `diffclass`) lists a branch difference with identical targets: `branch targets differ (1): jl at +0x1bb: ours to +0xa1, the original's to +0xa1`. Same on `ls_ReadPlayerSlots`: `jl at +0x1cc: ours to +0xaf, the original's to +0xaf`. The real difference in that loop is a 4-byte record-pointer bias (see improvement-reports/diffclass-ivbias-class.md). Worker's guess: the check compares the raw displacement or a pre-alignment target.
- **Expected:** report a branch only when the aligned targets differ, or say why (e.g. "displacement differs, same target").
- **Repro:** `uv run dcp grade ls_WritePlayerSlots` at gildegold commit 635eba0; `uv run dcp grade ls_ReadPlayerSlots` at 6292ee1.
- **Impact:** about 5 minutes ruling out a hidden control-flow difference; noise in the escalation reason.

## Also seen (match-base session 2026-11-01 (gildegold), worker 6)
- ai_PokerHighCard (0x4a76d0): `branch targets differ (10): jge at +0x15: ours to +0x1c, the original's to +0x1c`; same entry in the B3 line of `dcp grade`. Inflates the "branch N" count.
- Repro: the pre-session draft (`git show f47bfc6:src/unk_4a7140.c`), then `uv run dcp diffclass ai_PokerHighCard`.
- Proposal: drop entries with equal targets, or print offsets relative to the aligned position.

## Also seen (match-base session 2026-11-01 (gildegold), worker 13)
- sv_BorderCameraView: "ours to +0x326, the original's to +0x326".

## Also seen (match-base session 2026-11-02 (gildegold), worker 23) - critical, FIXED in 5469812
- gv_BuryCharacter (0x4f0240) at gildegold f63aefb: `je at +0x11b: ours to +0x131, the original's to +0x131` turned an otherwise shape function (single `order 42` hunk, ecx/edx swap plus one `mov edx, edi` moved across the `jle`) into verdict=draft / `B3 draft: order 42, branch 1`. Worker stopped the session as critical.
- **Root cause** (`src/diffclass.rs`, `aligned()`, used by `branch_diffs` / `same_code`): jump targets are mapped through the alignment, but inside an `order` hunk lines were paired by raw text, while the order class only matches after the hunk's register renaming. Ours' target `mov eax, edx` (+0x131) paired with the original's other `mov eax, edx` at +0x125 instead of its `mov eax, ecx` at +0x131, so the target looked different.
- **Fix:** new `order_keys()` pairs an order hunk's lines by the texts the class compared (ours renamed via `x86::rename_registers` from the hunk note; esp-normalised for "order across a push / pop" hunks; `x86::esp_normalised` now `pub`). A stricter "same instructions from target to hunk end" rule was tried and reverted (turned 12 shape functions into draft, e.g. ai_Unk49a5b0). Synthetic test added to `diffclass::tests::branch_targets`; `cargo test` 187 passed, 0 failed.
- **Effect across gildegold's 1881 non-byte functions:** draft -> shape only gv_BuryCharacter; branch line gone for he_Unk546c40 (still draft); branch count -1 for ai_AddEquipmentNeeds and init_LoadBuildingScene; +1 for d2_PlotLine (`jne at +0x46: ours to +0x2d, the original's to +0x2d` where the target lines really differ, `[esp+0x30]` vs `[esp+0x34]`, previously hidden by positional pairing; the message wording there is still confusing, see below).
- The earlier sightings (ai_PokerHighCard, sv_BorderCameraView, ls_*PlayerSlots) come from older drafts and could not be re-checked; if "same target" reports recur they have another cause.
- **Remaining wording issue:** when the target lines are genuinely different instructions at the same offset (d2_PlotLine), "ours to +0x2d, the original's to +0x2d" still reads as identical; the message should say the target instructions differ.


## Also seen (match-base session 2026-11-02 (gildegold), worker 50) - after the fix in 5469812
- Recurs: in ai_GraveDetail (0x582b40), after replacing the `count` local with `for (i = 0; i < gv_EntryCounts[e->size]; i++)`, `dcp grade` / `dcp diffclass` printed `branch targets differ (2): ... je at +0x49: ours to +0x62, the original's to +0x62`. The identical-target entry still counts toward "branch targets differ", which the skill reads as "statement structure differs, never deep". Repro: that edit at gildegold's iteration-3 wrap commit (after 0891251), then `dcp diffclass ai_GraveDetail`. Cost: a few minutes of doubt.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- Third time today: `dcp diffclass gm_HandOutMoney` (0x4fae50) reported "branch targets differ" with both sides going to +0xfe (f3gm, before 728c0d8).

## Also seen (match-base session 2026-11-02 (gildegold), worker 58) - now changes a grade
- Fourth time today, and this one holds a function at B3 draft instead of shape: `dcp diffclass` / `dcp grade gm_DailyCharacterStep` (0x4fbe90) report `branch targets differ (1): je at +0x514: ours to +0x53d, the original's to +0x53d`. The target is the join point after the skill block, inside an FPU-only hunk; the checker seems to compare the instructions at the target (which differ only by FPU scheduling) rather than the target offsets. Repro: `dcp grade gm_DailyCharacterStep` at gildegold ca33582. The function was escalated with this flag still listed.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- gm_BuildKindObjects (0x500b90): `jne at +0x43: ours to +0x4b, the original's to +0x4b`. Fifth occurrence today (gildegold, before 9d14310).

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- `dcp grade gm_FreeBuilding` (0x5012e0): `branch targets differ (2): je at +0x26: ours to +0x4c, the original's to +0x4c; jne at +0x3e: ours to +0x4c, the original's to +0x4c`. Sixth occurrence today.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- `dcp diffclass gm_ListWorkers` (0x502eb0): `jmp at +0x97: ours to +0xf6, the original's to +0xf6` among 8 entries (the others only shifted because ours is a few instructions longer). Seventh occurrence today; `dcp escalate` accepted the function. Cost: ~10 minutes. Repro: the commit before its escalation (before 68a0e3c).
