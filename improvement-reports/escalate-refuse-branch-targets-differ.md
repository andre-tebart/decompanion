# `dcp escalate`: refuse while branch targets differ or `code` hunks dominate

- **Source:** match-base session 2026-11-02 (gildegold), worker 47 (coordinator review)
- **Area:** `dcp escalate`, match-base skill section 3
- **Problem:** ai_CannonScene (0x57e270) was escalated as "only allocation is left" with diffclass `code 485, regs 144, slots 142, branch 22` and 12 differing branch targets: statement structure, not allocation. Earlier the same day ai_AlchemistResearchWindow went to deep with 4 differing branch targets and code 224. The skill forbids both, but `dcp escalate` only checks the instruction-count difference and the reason's wording, so the escalation went through.
- **Proposal:** escalate refuses while diffclass reports `branch targets differ` (structure: base work), and while `code` hunks exceed a share of the differing lines (e.g. half) unless `--code-explained "<hunk: why>"` names each one. Print the diffclass summary in the refusal.
- **Repro:** `dcp escalate ai_CannonScene "..."` at gildegold 76084c9.
- **Cost of not having it:** a whole worker session spent on one premature escalation, plus a coordinator review and rework. Related: skill-shape-vs-escalate-guidance.md, grade-show-instruction-counts.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 48)
- ai_CannonScene, ai_CannonAim and ai_CannonCamera bounced base -> deep -> base three or four times (cf8244e, 4aea082, 83fdff3 ...): `dcp escalate` accepts, a later review clears the tag on criteria escalate could check itself (unexplained `branch targets differ`, `code` hunks). The whole first item of this session was a redo.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- `dcp escalate ai_OpenItemTooltip` (0x588310) was accepted although branch targets still differ; the worker's reason: the original lays an if/else chain's blocks inline, our compile moves them after the chain, five source forms didn't change it. The worker itself flagged it for review. Wrap d8ce059.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- `dcp escalate gm_CharNameRecord` (0x4fb390) accepted with "branch targets differ" listed (ours keeps two locals on the stack where the original uses registers; several statement structures compiled identically). The skill says that verdict is "never deep", escalate accepts it: ~20 minutes on structural variants. Want escalate to name the case "targets differ only by block placement" (or refuse), or the skill to say how to prove it.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- `dcp escalate gm_DailyCharacterStep "..."` accepted with no warning while diffclass listed `branch targets differ (1)` (a false one here, see ../bug-reports/grade-branch-targets-differ-same-target.md). Want refuse, or warn and require the jump to be named in the reason.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- `dcp escalate gm_FindHome` (0x4fd820) accepted (`action='@deep added'`) while diffclass said `branch targets differ (1): je at +0x30`. Moving the fallback under `if (pick == 0)` made the targets equal; the reason then had to be replaced. Want escalate to refuse as it does on a large instruction-count gap. Cost: one wrong escalation and a re-escalate.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- gm_CollectOffers and gm_BuildNext: differing targets came only from blocks VC6 placed differently (no statement differed); `dcp escalate` accepted all three (with gm_BuildKindObjects' identical-target one). Want pairs equal after alignment dropped, and a `layout-only` tag when the target block's instructions are equal and only its position differs, so the skill's rule and the tool agree. Cost: ~10 minutes of extra rewrites.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- gm_BuildingMainObject (0x501b50): three differing targets came only from epilogue sharing (the original holds `o` in eax after the shared query call, ours in ebx), i.e. allocation; `dcp escalate` accepted it. Want diffclass to say whether a differing target only lands on another copy of an equivalent epilogue/return sequence, and the skill to allow that case explicitly. Related: diffclass-tail-epilogue-class.md
