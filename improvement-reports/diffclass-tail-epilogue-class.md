# diffclass: a class for merged and duplicated return tails

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** diffclass, escalate
- **Problem:** in `rd_BuildRoad` the original keeps three identical `call d3sm_Destroy; …; ret` fail blocks, and our compile merges them into one (`push edx; jmp X`). In `d2_OpenForm` it is the other way round: the original shares the two `return -1` epilogues. Both show up as plain `code` hunks plus wrong branch targets, so they look like meaning differences.
- **Proposal:** a `tail`/`epilogue` class. It applies when one side jumps to a block that is instruction-identical (apart from registers) to a block the other side has inline. `escalate` should then accept the instruction-count gap without `--size-explained`.
- **Cost of not having it:** high. It took most of the time spent on `rd_BuildRoad`, including two experiments.

## Also seen (match-base session 2026-11-01 (gildegold), worker 4)
- **Cross-jumping of call sites, not just epilogues:** in ai_EvaluateProductionFlags, VC6 merged three `ai_SendJobOrders` call sites into one in ours where the original kept three. In ai_FindPartner the original has 7 epilogues, ours 3. diffclass reports both as large `code` hunks.
- **Proposal:** label it `crossjump` when one side has N similar call sequences and the other 1 plus `jmp`s, so workers can stop and escalate sooner.
- **Repro:** `uv run dcp diffclass ai_EvaluateProductionFlags` at gildegold commit d5c27ec, hunk at 0x480041.
- **Cost:** about 10 minutes trying source variants before escalating.

## Also seen (match-base session 2026-11-01 (gildegold), worker 6)
- ai_PokerNpcFold: ours merged one case's tail into another (`push 4; jmp X`), the original didn't; every line after showed as shifted `code`. The real fix was elsewhere (where `&seat[j]` is computed), and nothing hinted that the layout came from a merge. Proposal: diffclass names "ours jumps into another block's tail (cross-jump) at +0x..". Cost: about 3 failed variants.

## Also seen (match-base session 2026-11-01 (gildegold), worker 7)
- Both escalations came down to VC6 return-block replication: ai_PokerShowdown (original gives each `winHand = kind[2]; return 2` its own `pop/add esp/ret`, ours shares one) and ai_DecideBuildingResident (identical case tails merged in the opposite direction). All `code` + `branch`, so draft, and escalation needed `--size-explained`. Cost: about 20 minutes before escalating.

## Also seen (match-base session 2026-11-01 (gildegold), worker 10)
- ai_TrustedOfFour: 146 vs 162 instructions, entirely from three duplicated 5-instruction `return -1` epilogues; needed `--size-explained`. Proposal: diffclass recognises "identical epilogue inlined vs shared" and `dcp escalate` subtracts it from the size gate automatically.

## Also seen (match-base session 2026-11-01 (gildegold), worker 14)
- sv_HoverPick: the original places the early-out block inline with its own epilogue; ours places it last and shares the final epilogue. diffclass shows two 31-line `code` hunks of identical instructions in different positions. Proposal: a `layout` (block moved) class for a whole basic block relocated together with its epilogue.

## Also seen (match-base session 2026-11-02 (gildegold), worker 16)
- Skill line wanted (section 2.2): a push sequence repeated per branch that jumps into one shared call means separate calls per branch in the source (VC6 cross-jumps them). Needed in three functions: `d3if_ScreenBox` in sv_DrawBubbles, sv_DrawGateName's `gm_Query` and `sprintf`, sv_SpeakPicked's topic grading. The reverse (our identical tails merged where the original kept them apart) happened in sv_CameraFollow's double selection check. Cost: ~4 builds per function before spotting the pattern.

## Also seen (match-base session 2026-11-02 (gildegold), worker 23)
- gv_AllocGraveyard: the only real difference is block placement (out-of-memory cleanup inline in the original, at the end in ours); diffclass says `code 136`. Another case for the `layout`/`block` class. Cost: ~5 minutes of variants.

## Also seen (match-base session 2026-11-02 (gildegold), worker 29)
- ai_Unk48e120: the original shares one "borrow" tail between two branches via a `jmp` into it; ours keeps both inline. diffclass said `code 32`; ours is 12 instructions longer, exactly at the escalate limit (193 vs 181). A note like "the original reaches this sequence by a jmp from +0x210" would have saved ~5 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 30)
- Three of seven escalations came down to shared vs duplicated endings: ai_DecideBuildSculpture, ai_DecideUseAlchemyItems, ai_ExecSecretRoom1; each 10-20 instructions, shown as large `code` hunks plus `branch targets differ`. Proposal repeated: a detector saying "ours/original jumps into a shared ending at X; the duplicated block is N instructions", subtracted from the escalate size check. Cost: ~10 minutes per function.

## Also seen (match-base session 2026-11-02 (gildegold), worker 36)
- ai_DecideThreaten: VC6 merges the tails of three `ai_ChooseSubAction` calls at different depths on each side; the original's jumps land mid-way through the shared argument pushes. Reported as `code` plus "branch targets differ". Note wanted: "jmp into a shared call sequence at another depth: call tails merged differently (scheduling)" - would have saved ~4 restructuring builds. Repro: `uv run dcp diffclass ai_DecideThreaten`.
