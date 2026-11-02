# Naming per-kind event fields: per-kind union views in one header

- **Source:** match-base session 2026-11-02 (gildegold), worker 33
- **Area:** typing / Q2
- **Problem:** `AIJOBX.unkb0..unkbc` hold different things per event kind, so no single name fits and Q2 keeps ai_EvalLeastLikedOfEvent (0x496b10) at readability draft. A `price` member at +0xb0 was added to `AIJOBX` for the buy-building events. Adding it to ai.h's `AIJOB` instead dropped ai_Unk483a60 from byte to shape (declaration-set tie-break), so it lives in am.h (`Open:` line in am.c). The same per-kind pattern appeared earlier for AIJOB's `partner1`/`partner2` unions (see ../bug-reports/grade-q2-ignores-union-alias.md).
- **Proposal:** a supported convention for per-kind union views of one record in a single header (e.g. `union { struct {...} buy; struct {...} pair; }`), with Q2 accepting a field reached through the view matching the function's event kind; possibly a helper to generate the view from observed offsets per kind.
- **Cost of not having it:** functions stuck at readability draft; ad-hoc duplicate struct views.
- **Related:** types-duplicate-views-lint.md, fall-trigger-and-include-chain.md
