# Lint / `dcp types dup`: list struct types that describe the same record

- **Source:** match-base session 2026-11-01 (gildegold), worker 8
- **Area:** new command / lint
- **Problem:** the 0x21c character record has many views with different field names: `AIPER` (am.h), `AIPX` / `AIARGX` (am.c), `AICHAR` (ai.h), `AMTCHARVIEW`, `G16CHAR`, ... (ai.h calls 0x194 `money`, am.h had `unk194`). Likewise `G10DIST` duplicates `AMTKIND`, `G10DREC` duplicates `AMTREC`. Every function costs a decision about which view to use, and names diverge.
- **Proposal:** `dcp types dup` (or a lint) listing struct types with the same size and overlapping field offsets, showing conflicting names per offset, to drive unification.
- **Repro:** grep the views above at gildegold 7ae5254.
- **Cost of not having it:** a few minutes per function.

## Also seen (match-base session 2026-11-02 (gildegold), worker 15)
- D3OBJECT+0x1d4 is `float radius` in d3.h but D3OBJX (d3_engine.h) has `void *events` there, and d3_engine.c uses it as events. The worker first invented a duplicate `D3EVENTSLOT` before finding `D3EVENT` (~10 minutes plus an undo commit). Proposal addition: `dcp why` or a type-at-offset query listing every struct field declared at the same base+offset across headers.

## Also seen (match-base session 2026-11-02 (gildegold), worker 30)
- `#define ai_TimeT (*(AITIME *)&ai_Time)` is defined separately in 10 units (ai, am, gv, hmt, hst, ls, main, sv, unk_4a7140, unk_4b39f0); am.h also keeps raw `TMX`/`NOWX` macros that keep Q4 on every am function copying the clock. AHMCLOCK (ahm.h) and AITIMEX (am.h) duplicate each other. Proposal addition: lint "same view macro defined in N units", and one declared typed view in a shared header. Cost: a few minutes per function.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- The same `AITIME` view macro is redefined per unit (ai.c, am.c, hmt.c, hst.c as `ai_TimeT`; gv.c as `gv_TimeT`); f3gm got one more. Want a shared header entry (e.g. a time view header) or a `dcp headers` suggestion.
