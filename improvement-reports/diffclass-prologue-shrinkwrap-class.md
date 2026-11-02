# diffclass: a `prologue`/`shrinkwrap` class for callee-saved pushes placed after an early return

- **Source:** match-base session 2026-11-02 (gildegold), worker 52
- **Area:** `dcp diffclass`, escalate
- **Problem:** in ai_GraveFogWindow the original saves ebx/esi/edi at the start; ours saves them after the early return. diffclass called it `code` plus "branch targets differ", though the only cause is the resulting 3-byte shift. The branch warning suggests wrong statement structure (the skill's "never deep" signal).
- **Proposal:** classify moved callee-saved pushes/pops around an early return as `prologue` (allocation), and discount branch targets that differ only by that shift.
- **Repro:** `dcp diffclass ai_GraveFogWindow` (0x585380) at gildegold 1a594b8.
- **Cost of not having it:** ~5 minutes trying two control-flow variants before escalating.
- **Related:** diffclass-tail-epilogue-class.md, ../bug-reports/grade-branch-shift-noise.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- gm_SpawnCharacter (0x4fddb0): the only differences were where `push edi` / `push esi` and their pops sit; diffclass said `code 22` (verdict draft), proven hunk by hunk. Want a `saves` class (callee-saved push/pop moved plus the following esp-offset shifts), counted like `frame`. Cost: ~10 minutes, 4 rebuild trials.
