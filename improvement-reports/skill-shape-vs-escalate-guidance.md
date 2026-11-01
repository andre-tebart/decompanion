# match-base skill: say when scheduling-only "code" hunks allow a shape claim

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp-match-base skill
- **Problem:** 6 of 8 functions were escalated with only allocation or scheduling differences left. The skill does not say clearly when `diffclass` "code" hunks that are really scheduling allow a shape claim (or an `accept`) rather than an escalation.
- **Proposal:** add that guidance to the skill (and see diffclass-sched-and-regs-with-copy.md for the tooling side).
