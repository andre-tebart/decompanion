# diffclass: a `moved`/`layout` class for a block placed elsewhere

- **Source:** match-base session 2026-11-03 (gildegold), worker 70
- **Area:** `dcp diffclass`
- **Problem:** in gm_ForfeitEstate (0x506e70, 595 instructions both sides) the same 20 instructions (house-owner condition block) sit inline in the original and at +0x66b in ours; diffclass reports them as `code`. The function was escalated to deep for exactly this.
- **Proposal:** recognise an identical instruction run that only changes position (plus the jumps into/out of it) as a `moved`/`layout` class.
- **Repro:** `dcp diffclass gm_ForfeitEstate` (gildegold befd916).
- **Cost of not having it:** part of ~40 minutes of variant trials over three escalations; a clear class would have allowed an earlier, more confident escalation.
- **Related:** diffclass-sched-and-regs-with-copy.md, diffclass-tail-epilogue-class.md
