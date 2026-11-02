# diffclass: an `order`/`sched` class for a moved store, and `regs` that tolerates one copy

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** diffclass (related: asmdiff-regs-auto.md)
- **Problem:**
  - In `lobby_Screen`, one `mov dword ptr [d2_ClickedId], -1` placed a few instructions earlier became two 1-line `code` hunks.
  - A loop with ecx/edx swapped plus one extra `mov edi, ecx` copy became one 102-line `code` hunk.
  - The same happened in `snd_UpdateRain`, where a handle is loaded before or after `_ftol`.
- **Proposal:** an `order`/`sched` class for a single store moved within a basic block, and a `regs` class that tolerates one copy instruction.
- **Repro:** `dcp diffclass lobby_Screen` at gildegold commit 7a4cb71.
- **Cost of not having it:** several functions went to deep rather than shape.

## Also seen (match-base session 2026-11-01 (gildegold), worker 3)
- **Slot-shifted, misaligned block counted as `code`:** in `lobby_ChoosePlayer`, hunks 0x58b595 and 0x58b5bd (27 and 33 lines) are the same instruction sequence. They differ only by stack slots, but the alignment slipped by a few instructions. Repro: `uv run dcp diffclass lobby_ChoosePlayer`. Cost: about 5 minutes reading asmdiff.
- **Push moved to the prologue counted as `code`:** in `lobby_ShowCity`, the original pushes ebx/esi/edi at entry and ours pushes them at the join, so every stack offset in between is +0xc. diffclass says "code 113" for pure scheduling plus a frame shift. Proposal: a `prologue`/`pushes` class, or `frame` alignment that also covers this case. The function stays draft when it is really shape.

## Also seen (match-base session 2026-11-02 (gildegold), worker 18)
- sv_UpdateBand / sv_UpdateBandLed: the original loads `info` into ecx then `mov eax, ecx` before `mov ecx, 8`; ours loads straight into eax. One inserted reg-to-reg copy from allocation, reported `code 17`, so draft. Repro: `uv run dcp diffclass sv_UpdateBand` (gildegold 92add7d). Cost: ~10 minutes of variants before escalating two functions.

## Also seen (match-base session 2026-11-02 (gildegold), worker 69)
- gm_TakeOverCharacter (0x5064d0): swapping an if/else moved code hunks 145 -> 121; reordering four struct-field stores 71 -> 61. Load/store reordering around `rep movsd` and around a pushed call argument is counted as `code`, not `order`. Main reason the function was escalated rather than graded shape. Repro: `dcp diffclass gm_TakeOverCharacter`, hunks at +0xf0..+0x120 (gildegold 33968a7).

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- gm_CreateCharacter init block: same stores in another order plus a register rename and -1 as an immediate vs in a register; `order` did not catch it, code count 132. Part of ~40 minutes over three escalations.
