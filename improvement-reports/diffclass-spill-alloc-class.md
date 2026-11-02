# diffclass: a `spill`/`alloc` class for a value kept in a register on one side and a stack slot on the other

- **Source:** match-base session 2026-11-01 (gildegold), worker 6
- **Area:** `dcp diffclass`, `dcp asmdiff`
- **Problem:** when the only difference is register allocation and it changes the frame (one extra saved register, a spilled variable), the extra push/pop and spill/reload instructions shift every stack offset and the whole block is classed `code`:
  - ai_PokerPickStrategies: `code 125, branch 16, slots 16, frame 6, regs 4` (vars `s` and `dealt` spilled instead of kept in ebp/dl);
  - ai_PokerOpenCounts: `code 84` (the zero constant held in edi; the original uses eax, ecx and immediates).
  Shape is unreachable for functions whose meaning is complete, and the escalation reason has to prove allocation by hand.
- **Proposal:**
  - a `spill`/`alloc` class for hunks where one side loads/stores the same slot and the other uses a register; at minimum a hint such as "differs by one saved register (edi)";
  - in asmdiff, when ours pushes a register the original doesn't, say what lives in it, e.g. "edi holds the constant 0 across 12 uses", pointing at the cause (a function-wide constant, a spilled loop variable).
- **Repro:** `uv run dcp diffclass ai_PokerPickStrategies` / `ai_PokerOpenCounts` at gildegold commit 2fb619b.
- **Cost of not having it:** 5-10 minutes per escalation (3 this session) plus 4-5 source variants tried per deep function; the main time sink of the session.
- **Related:** asmdiff-regs-auto.md, diffclass-sched-and-regs-with-copy.md (prologue push item), ../bug-reports/diffclass-rotation-with-reorder-as-code.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 7)
- Constants held in registers: in ai_DecideBuildingResident the original loads repeated call constants into registers (`mov esi, 0x807d4190` / `mov edi, 1`, then `push esi` / `push edi` at both calls) while ours pushes immediates. diffclass says `code`. Proposal: classify `push reg` (reg holding a known constant) vs `push imm` as `regs`. Cost: two fruitless variant builds.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 11)
- When ours has more instructions because of a spilled strength-reduction induction temp, `ours=` / `original=` doesn't explain it; an asmdiff head note like "induction variable spill at [esp+X]" would help the escalation reason.

## Also seen (match-base session 2026-11-01 (gildegold), worker 14)
- FPU home: in sv_RefreshPanel the original keeps `prog` in st(0) (`fld 0.05f`, `fld st(0)`, `fst [slot]` before calls); ours stores immediates to the slot (`mov [esp+0x14], 0x3d4ccccd`). Shown as `code`. Proposal: an `fpu-home` class read as allocation.

## Also seen (match-base session 2026-11-02 (gildegold), worker 15)
- Zero/constant registers: in sv_HandleSelectionMouse the original holds 0 / -1 / 1 in ebx / edi / ebp, using `cmp [mem], reg` where ours does `mov eax,[mem]; test eax,eax`; ~15 extra instructions in one variant, past the max(12, 1%) escalate limit. Proposal: classify the pair as allocation and discount it in the size check.

## Also seen (match-base session 2026-11-02 (gildegold), worker 17)
- sv_ButtonRow / sv_TabButtonRow: the only non-rotation lines were `cmp eax, ebx` (ebx = 0) vs `test eax, eax`, and `cmp byte [X], bl` vs `mov al,[X]; test al,al`. They kept the prologue hunk `code`, so both escalated instead of shape. Proposal: a compare against a register known to hold 0 counts as `test` (regs).

## Also seen (match-base session 2026-11-02 (gildegold), worker 22)
- gv_GraveCount: the original holds 1 in a register (`mov dl, 1; cmp bl, dl`), ours compares with the immediate. It looked like allocation (the worker tried a char type change), but the cause was control flow: tail-merged `if (x == 1) n += k` arms with one final return vs early returns; an if / else-if chain with one return gave byte. Hint wanted: a constant held in a register usually follows from block structure / tail merging, not types. Cost: 3 builds.

## Also seen (match-base session 2026-11-02 (gildegold), worker 27)
- Local copy of a global: in gv_RetireCrime `player = ai_PlayerId` reloaded after a call got its own slot (`mov word ptr [esp+0x18], dx`, twice); the original keeps it in a register. Using `ai_PlayerId` directly gave byte. Hint wanted when a slot store of a register directly follows a global load and the original has the load without the store: "use the global instead of a local". Repro: `uv run dcp asmdiff gv_RetireCrime` at gildegold df8a26c^ with the local restored. Cost: ~5 minutes; nearly escalated a byte-matchable function.
