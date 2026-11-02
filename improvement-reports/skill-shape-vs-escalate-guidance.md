# match-base skill: say when scheduling-only "code" hunks allow a shape claim

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp-match-base skill
- **Problem:** 6 of 8 functions were escalated with only allocation or scheduling differences left. The skill does not say clearly when `diffclass` "code" hunks that are really scheduling allow a shape claim (or an `accept`) rather than an escalation.
- **Proposal:** add that guidance to the skill (and see diffclass-sched-and-regs-with-copy.md for the tooling side).

## Also seen (match-base session 2026-11-01 (gildegold), worker 11)
- sv_UpdateMemberList reached byte but readability is blocked only by a unit head conflict (Q4/Q7: sv.c can't include d2.h/gfx.h). The skill doesn't say whether that counts as raised or must be escalated; the worker committed it as "byte (match-base)" and counted it. One sentence on this case would remove the doubt.

## Also seen (match-base session 2026-11-02 (gildegold), worker 33)
- `--size-explained` is framed around allocation (spills, saved registers), but in 3 of 8 functions the gap came from compiler-made epilogue copies or tail merging (both directions: 0x497660 has extra copies, 0x4979d0 / 0x498470 merged ones, 0x497fa0 an unmerged credit-check tail). Skill sentence wanted: such copies/merges of identical code also count, with the asmdiff lines that show it.

## Also seen (match-base session 2026-11-02 (gildegold), worker 34)
- ai_ExecuteCitizenship: the only code hunks were callee-saved push/pop placement (original saves ebx/esi/edi after the two early returns, ours in the prologue). Skill section 3 wants a one-line example list: prologue push placement (shrink-wrapping), constant registers, tail-merge of identical return blocks count as allocation/variant work.
