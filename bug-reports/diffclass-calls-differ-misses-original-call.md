# diffclass `calls differ` says the original never calls a callee it does call

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Severity:** minor
- **What happened:** `dcp diffclass ai_CannonExplosion` printed `calls differ: ours cm_GetSlotState x1 | the original none`, but the original calls 0x4c3ae0 <cm_GetSlotState> at 0x5808a6 (`dcp disasm` shows it).
- **Expected:** both sides x1, no `calls differ` line.
- **Repro:** `dcp diffclass ai_CannonExplosion` at gildegold 39f10ee.
- **Impact:** small, but it cast doubt on a correct reconstruction.
- **Related:** asmdiff-symbols-wrong-library-callee.md, asmdiff-symbols-original-side-new-object-unresolved.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 49)
- Same message on `dcp asmdiff ai_CannonExplosion --symbols`: `calls differ: ours cm_GetSlotState x1 | the original none`. Here ours called it twice (rotated loop) and the original once, so the line appears to list only the surplus over the other side, which reads as "the original never calls it". Want counts on both sides: `cm_GetSlotState ours 2 / original 1`. Cost: a few minutes re-reading the original's disassembly.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53) - tail calls
- `dcp asmdiff ai_GraveInsuranceContact --symbols` (starting draft) said `calls differ: ours none | the original sv_ClearSelection x1`, though our draft already called sv_ClearSelection. The real missing call was the trailing `jmp sv_CameraFollow` (tail call): tail jmps appear not to be counted as calls, so the count shifts onto the previous callee. Repro: any function whose last call is a tail `jmp`, with the C missing it. Cost: ~1 call reading the end of `dcp disasm`.
