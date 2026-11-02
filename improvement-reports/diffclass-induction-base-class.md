# diffclass: a `base` class when a loop pointer walks a different field of the same record

- **Source:** match-base session 2026-11-02 (gildegold), worker 16
- **Area:** `dcp diffclass`
- **Problem:** in sv_DrawBubbles and sv_DrawNamePlates our loop pointer walks one field of the record and the original's another (`mov ebx, sv_NamePlates+0x48` vs `mov ebx, sv_NamePlates`), so every access differs by a constant (`[ebx-0x48]` vs `[ebx]`, `push ebx` vs `lea edx,[ebx+0x48]`). This shows as `code` and blocks shape though it is an addressing choice.
- **Proposal:** recognise "same loop, base register offset by a constant" as a shape class (`base`).
- **Repro:** `uv run dcp diffclass sv_DrawNamePlates` at gildegold e2a566e.
- **Cost of not having it:** 2 escalations that may be shape; ~8 builds of variants.
- **Related:** ../bug-reports/diffclass-address-mode-as-code.md, skill-index-loop-vs-pointer-walk.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 20)
- gv_WriteEffects and gv_ReadEffects: every statement matches; only the slot pointer bias differs (ours slot+0xc, original slot+0x38). Until the class exists, the skill could say to escalate this case without trying more spellings (3 tried).

## Also seen (match-base session 2026-11-02 (gildegold), worker 37)
- ai_DecideChangeProfession (gildegold 4bfac32): only the induction variables differ: the original keeps a running pointer and a byte-offset index (`cmp esi, 0x3c`), ours folds both into one counter (`cmp esi, 0xf`); same 15 iterations; frame 0xbc vs 0xac. Proposal: a `loop-iv: same trip count, other induction variables` annotation to tell source-shape from allocation. Cost: ~10 minutes of tries, escalated.
