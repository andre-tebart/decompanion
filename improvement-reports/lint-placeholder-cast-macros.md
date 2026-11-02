# Flag placeholder-named cast macros wrapping a real function

- **Source:** match-base session 2026-11-02 (gildegold), worker 31
- **Area:** Q1/Q2 / consistency
- **Problem:** macros like `AI_4A63F0_7` and `AI_5044B0_US` (address-plus-arity names around a real function) aren't flagged by Q1/Q2, and hid two meaning errors: an `__int64` mask split into two ints for ai_PickActionBuilding, and the wrong `unsigned short` parameter/return of gm_TitleJob.
- **Proposal:** a finding like "call through a cast view of X whose prototype is in f3gm.h", and Q2 treating such macro names as placeholders.
- **Cost of not having it:** ~10 minutes across three functions working out that the macros, not the call sites, were wrong.
- **Related:** cast-views-on-prototype-change.md, ../bug-reports/rename-leaves-stale-macro-name.md
