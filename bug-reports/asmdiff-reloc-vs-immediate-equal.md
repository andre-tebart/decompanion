# asmdiff shows a line as equal when ours is relocated and the original's is a plain immediate

- **Source:** match-base session 2026-11-02 (gildegold), worker 30
- **Severity:** minor in the gates, but a real run-time error in a relinked program
- **What happened:** at gildegold 3209111, `ai_Unk48f600` (now ai_DecideUseAlchemyItems) and `ai_Unk48ff50` (now ai_DecideGraveyardOwner0) in src/am.c had `flags = ((unsigned)&cm_SendRing + 0x4973c0);`. Ours emits `mov dword ptr [esp+0x18], 0xf00500` relocated against `cm_SendRing`; in the original `dcp refs` lists no operand reference at 0x48f84c, so it is a plain constant. `dcp asmdiff` showed the line as equal (no `!` / `=`); only Q3 flagging `0x4973c0` hinted at it. In a relinked image the value would move with `cm_SendRing`; no gate reports it.
- **Expected:** mark relocated-vs-absolute operand mismatches with `!` (or a class of their own), and count them as a meaning difference in grade.
- **Repro:** `uv run dcp asmdiff ai_Unk48f600` at gildegold 3209111; `uv run dcp refs` / `uv run dcp why 0xf00500`. Fixed in "am: ai_DecideUseAlchemyItems -> deep" and "am: ai_DecideGraveyardOwner0 shape + readable".
- **Impact:** ~5 minutes; silent run-time bug otherwise.
- **Related:** ../improvement-reports/lint-symbol-plus-offset-immediate.md, grade-q3-flag-constant-as-address.md
