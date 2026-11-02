# diffclass rejects `regs` when a register is reused after its old value dies (map can't change at a redefinition)

- **Source:** match-base session 2026-11-02 (gildegold), worker 37
- **Severity:** minor (shape function graded draft)
- **What happened:** ai_ExecuteMasterBuilder (0x49ea90): the only remaining hunk is 8 instructions where the original holds a value in eax and ours in esi (esi previously held the now-dead s1). Ours has `mov esi, dword ptr [esi + 0x10] / test esi, esi / cmp esi, 4 / fstp [esi*8+X]`, the original `mov eax, dword ptr [esi + 0x10] / test eax, eax / cmp eax, 4 / fstp [eax*8+X]`. Because `mov esi,[esi+0x10]` reads old esi and writes new esi, one global esi=eax map doesn't fit, so diffclass says `code 16` and the verdict stays draft. The worker escalated a function that is really shape.
- **Expected:** allow the rename map to change at an instruction that newly defines a register (the old value is dead after the overwrite); then the hunk reads `regs`. When `regs` is rejected, say why (`regs rejected: esi maps to both esi and eax`).
- **Repro:** at gildegold 47bbb96, `uv run dcp diffclass ai_ExecuteMasterBuilder --all`, `uv run dcp asmdiff ai_ExecuteMasterBuilder`.
- **Impact:** ~5 minutes; function held at draft in the ledger.
- **Related:** diffclass-rotation-with-reorder-as-code.md, diffclass-slot-permutation-per-hunk.md, ../improvement-reports/asmdiff-regs-auto.md
