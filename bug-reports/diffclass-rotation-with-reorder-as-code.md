# diffclass labels pure register rotations as `code` when mixed with small reorders

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Severity:** minor
- **What happened:** in `ls_ReadSceneRecords`, hunk `0x0051ebd6 code 50` is exactly ours `mov ecx,[esi+0x34]; lea eax,[esi+0x48]` vs the original's `mov edx,[esi+0x34]; lea ecx,[esi+0x48]`, one consistent rotation (eax->ecx, ecx->edx, edx->eax); neighbouring hunks with the same mapping are classed `regs`. Hunks 0x0051ea7c (42), 0x0051ecd3 (20), 0x0051ed71 (60), 0x0051ee99 (110) mix that rotation with small push/lea reorderings and also fall to `code`. `asmdiff --regs eax=ecx,ecx=edx,edx=eax` made it worse (346 -> 368 differing) because the mapping applies to the whole function while the rotation is local.
- **Expected:** classify a hunk as `regs+order` when it equals the original after a per-hunk register bijection plus a reorder; or allow `--regs` per address range.
- **Repro:** `uv run dcp diffclass ls_ReadSceneRecords --all` at gildegold commit 52c6fec.
- **Impact:** the largest cost of the session: 15-20 minutes reading ~400 hunk lines by hand; the function was escalated instead of graded shape.
- **Related:** improvement-reports/asmdiff-regs-auto.md, improvement-reports/diffclass-sched-and-regs-with-copy.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 5)
- main_CreateStartCouple (0x53b840): the only remaining hunk is a consistent eax<->ecx / al<->cl swap in one copy loop, classed `code 14` instead of `regs`. Possibly because eax also holds the random index just before the loop. The function stays draft though it is really shape.
- Repro: `uv run dcp diffclass main_CreateStartCouple` at gildegold commit f47bfc6.
- Cost: several build rounds trying source variants before concluding it was allocation.

## Also seen (match-base session 2026-11-01 (gildegold), worker 13)
- sv_BorderCameraView: a register rotation across identical blocks classed `code` (gildegold before baa6b2c).
