# `dcp rename` reports an M5 error just caused by an uncommitted edit as "1 from before"; build/grade don't show it

- **Source:** match-base session 2026-11-02 (gildegold), worker 28
- **Severity:** minor (nearly committed a gate failure)
- **What happened:** from ffcc056 the worker changed `unk_Unk4f4080`'s parameter to `unsigned short t` in include/gv.h and src/gv.c, then ran `dcp rename unk_Unk4f4080 gv_HeldCrimeIdsOf --why "..."`, which printed `check: 0 new error(s) after the rename, 1 from before`. "Before" meant before the rename, not the committed state, so the error read as old debt. It was M5: src/he.c:7377 and src/unk_58bbd0.c:20104 declare `int gv_HeldCrimeIdsOf();`, incompatible with a promoted parameter. `dcp build` and `dcp grade` (byte + readable, "consistency (M7) current") didn't show it; only `dcp check` did (`gate=FAIL why=errors=1`).
- **Expected:** count "from before" against HEAD / session base (or split "from uncommitted edits" vs "committed"); build/grade warn when a changed unit or header brings a new M5/M6; the M5 message names the cause ("unprototyped `int f();` in he.c / unk_58bbd0.c is incompatible with a promoted parameter (unsigned short); include gv.h or keep an int-sized type").
- **Repro:** `git checkout ffcc056`, make the parameter change (header + definition), run the rename above, then `uv run dcp build`, `uv run dcp grade gv_HeldCrimeIdsOf`, `uv run dcp check`.
- **Impact:** ~3 calls; caught only because the worker ran `dcp check` before committing.
- **Related:** ../improvement-reports/stale-local-prototype-flag.md, rename-refused-hand-written-name-other-signature.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 49)
- `dcp rename ai_Unk5821d0 ai_AlchemistLabContact ...` printed `check: 0 new error(s) after the rename, 1 from before`; the error was a new M1 fall (d3_CloneObject byte -> shape) caused minutes earlier by an uncommitted include/ai.h edit. Want "from the uncommitted changes" (the baseline was clean) and the error named. Cost: small.

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- `dcp rename ai_Unk584520 ai_GraveRentConfirm --why ...` ended with `check: 0 new error(s) after the rename, 1 from before (dcp check lists them)`, but the next `dcp check` (after build) was `gate=ok` with no error: the "from before" error was stale or transient and unnamed. Want the error named inline (`error=M6 at file:line`). Cost: one extra check, some doubt.

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- After `dcp rename unk_Unk4fa160 gm_IncomeKind3 ...`: `check: 0 new error(s) after the rename, 1 from before`; the error was ai_TutorialInitChapter2's M1 fall from the worker's uncommitted gv.h edit, absent at session start. Want comparison against the session baseline / HEAD and "1 from uncommitted changes". Cost: ~4 calls (suspected an earlier commit).

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- `dcp rename` said "1 from before" for an error from the worker's uncommitted gv.h change.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- Renaming ai_Unk889400 / ai_Unk76fdc4: `1 from before` was the D5 error the worker's own uncommitted edit had just caused (a tentative definition). Want the error named, e.g. `D5 0x76fdc4 gm_KindObjCount (src/f3gm.c:9425)`, or "from the working tree". Cost: one extra `dcp check` (~2 minutes).

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- After the gm_CatchMinorDisease signature edit, `dcp rename` printed `check: 0 new error(s) after the rename, 1 from before`; the one was the worker's own uncommitted M5.
