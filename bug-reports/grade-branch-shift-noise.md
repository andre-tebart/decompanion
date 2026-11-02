# Branch-target list repeats every jump shifted by one inserted/removed block

- **Source:** match-base session 2026-11-02 (gildegold), worker 33
- **Severity:** minor (misleading volume)
- **What happened:** for ai_ExecuteBuyBuilding (0x498470), `B3 draft: unexplained code hunks: code 5` came from a single early-return epilogue, but `branch targets differ` listed every jump that the resulting 4-byte shift moves (~12 lines), so the output looks much worse than the actual difference.
- **Expected:** collapse targets that differ only by one inserted/removed block into one line, e.g. "N targets shifted by +4 after 0x49847a".
- **Repro:** `uv run dcp grade ai_ExecuteBuyBuilding` at gildegold 2428e22.
- **Impact:** a few minutes per function.
- **Related:** grade-branch-targets-differ-same-target.md, ../improvement-reports/diffclass-tail-epilogue-class.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- `dcp diffclass gm_InitBuildingTables` (0x4fe370): all 10 "branch targets differ" entries were the same jumps landing on the same statements, offsets moved a few bytes (ours 20 bytes shorter). Since the skill reads that verdict as "never deep", it pushes toward a wrong conclusion. Want targets mapped through the alignment, reporting only jumps landing on unaligned code. Cost: moderate, several asmdiff reads before escalating. Related: grade-branch-targets-differ-same-target.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- gm_CreateObject and gm_Query: branch-target lines were offsets shifted by earlier size differences (+0x24e vs +0x256, +0x108 vs +0x107), aligned instructions identical. Want "targets equal after alignment". Verified by hand with `--side ours --symbols`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66)
- gm_KillSpieler (0x503c60): `jmp at +0x72: ours to +0x84, the original's to +0x88`, same place in the code; the original's target is its one extra instruction (`mov ebx,[esi+4]`, absent in ours). Want a target on an unpartnered instruction treated as the same target, so an allocation-only difference does not keep the "structure differs" verdict. Cost: ~2 extra checks.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- gm_ClassTreasury (0x5049e0, earlier version): `branch targets differ (3): jne at +0x48: ours to +0x94, the original's to +0x99; ...`, all to the same logical exit, 5 bytes later in the original because of an extra `push esi` / `xor esi,esi` and `mov eax,esi` exit. The real cause was a statement form (result held in a variable and returned at the end), but the evidence pointed at a saved register. Want `targets differ only by a shifted common exit (+0x94 / +0x99)`. Cost: ~6 build/grade rounds.
