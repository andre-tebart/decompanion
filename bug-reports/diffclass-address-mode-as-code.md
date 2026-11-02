# diffclass labels pure addressing-mode choices as `code`

- **Source:** match-base session 2026-11-01 (gildegold), worker 11
- **Severity:** minor
- **What happened:** equivalent address computations count as `code` hunks:
  - `mov cl,[eax+ebp]` vs `mov ecx,eax; add ecx,ebp; mov cl,[ecx]` (sv_UpdateGroundplan 0x522c86);
  - `[ecx*4+0xf8f38c]` and `lea eax,[ecx*4+d2_Wins]; [eax+6]` vs `shl eax,2; [eax+disp]`, twice (sv_UpdateCityPanel).
  Three functions stayed draft and were escalated with no meaning left to fix.
- **Expected:** an `addr`/`isel` class (counted like regs/sched) when both sides compute the same effective address from the same registers/symbols.
- **Repro:** `uv run dcp diffclass sv_UpdateGroundplan` / `sv_UpdateCityPanel` at gildegold 80355b6.
- **Impact:** ~15 minutes of source variants (pointer local, `char *` index, id types).
- **Related:** diffclass-rotation-with-reorder-as-code.md, ../improvement-reports/diffclass-spill-alloc-class.md, ../improvement-reports/diffclass-arg-slot-reuse-class.md
