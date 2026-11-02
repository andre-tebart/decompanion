# Lint: a callee declared `void` whose result the original reads (and return-type casts at call sites)

- **Source:** match-base session 2026-11-02 (gildegold), worker 21
- **Area:** lint / grade
- **Problem:** cm.c declared `void ai_Unk4c6260(void *p)`, but the original gv_FireShots stores eax after each call. Our code compiled only via a call-site cast `((int (*)(int))ai_Unk4c6260)(m)`; nothing pointed at the void declaration (now `cm_SendShots` returning the result of `ai_Unk4c39c0`).
- **Proposal:** flag callees declared `void` whose original call sites use eax right after the call, and call-site casts to a different return type.
- **Repro:** src/gv.c, calls inside `unk_Unk4eeb70` at gildegold 9aad298.
- **Cost of not having it:** ~3 minutes.
- **Related:** asmdiff-param-type-mismatch-hint.md, headers-signature-dry-run.md
