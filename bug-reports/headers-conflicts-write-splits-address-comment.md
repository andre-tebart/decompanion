# `dcp headers conflicts --write` inserts the include between an address comment and its definition

- **Source:** match-base session 2026-11-01 (gildegold), worker 13
- **Severity:** minor
- **What happened:** at gildegold ba38c66, `uv run dcp headers conflicts sv include/f3gm.h --write` reported `write=src/sv.c included=f3gm.h at=495 dropped=6`. The `#include "f3gm.h"` landed between `/* 0x520fe0, checks the character ... */` and `int sv_CheckCharacterFlag(int id)` (just before the first use of `gm_FindCharacterByMaster`). `dcp check` then failed with L.src (no address comment above the definition), M.gen (`_sv_CheckCharacterFlag` with no address comment) and M1 (no grade). `--trial` had just reported `falls=0` for the same layout.
- **Expected:** insert at the end of the head region (above the first function), or at least above the first user's address comment; `--trial` should run the L.src / M.gen checks. The head position compiled cleanly with no falls (fix in 348a817).
- **Repro:** the command above at ba38c66.
- **Impact:** ~4 tool calls, 5 minutes; the skill tells workers to rely on `--write`.
- **Related:** headers-conflicts-trial-silent-with-supersedes.md, grade-lost-address-comment-silent.md, ../improvement-reports/headers-conflicts-output.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 15)
- At gildegold 0070e09^ (after 697edf3), `uv run dcp headers conflicts sv include/ch.h --write` reported `write=src/sv.c included=ch.h at=425`; the include landed between `/* 0x520f20, resets the screen clip ... */` and `void sv_ResetScreenClip(void)`. `dcp check`: `error debt M1 0x00520f20 sv_ResetScreenClip ... no grade now (its source is gone?)`. Fixed by hand in 11b1173. Cost: ~3 minutes, one extra build/check.
- The M1 wording "its source is gone?" misleads when the cause is a detached address comment; it could say "address comment not directly above a definition?".

## Also seen (match-base session 2026-11-02 (gildegold), worker 20)
- Third occurrence. At gildegold 9bc6a23^ (after switching sv.c's K&R `void d2_PlaceMainWindow();` to the `d2_PlaceMainWindowF` cast macro), `uv run dcp headers conflicts sv include/unk_5d33b0.h --write` printed `write=src/sv.c included=unk_5d33b0.h at=403`: line 401 `#include "ch.h"`, line 402 `/* 0x520f20, resets the screen clip ... */`, new include at 403 directly above `void sv_ResetScreenClip(void)`. Check: L.src, M.gen, false M1. Fixed by hand in 9bc6a23. Cost ~5 minutes. Note the insertion point is always right after the previous include, which here sits just above an address comment.

## Also seen (match-base session 2026-11-02 (gildegold), worker 48)
- Fourth occurrence. `dcp headers conflicts unk_575860 unk_5d33b0.h --write` put the include at `at=765`, between ai_TutorialTick's address comment and its definition. `dcp check`: M1 `ai_TutorialTick ... no grade now (its source is gone?)`. Removed by hand.
- New detail: the worker had already added `#include "unk_5d33b0.h"` by hand near line 749, so `--write` added a **duplicate**. It does not check whether the header is already included.

## Also seen (match-base session 2026-11-02 (gildegold), worker 49)
- Fifth occurrence. `dcp headers conflicts unk_575860 ai.h --write` put the include at line 1208, between ai_QueryDefault's address comment and its definition: L.src / M.gen errors and an M1 on ai_QueryDefault. `--trial` without `--at` had reported `falls=0`, so the trial does not test the layout `--write` produces. Workaround: `--write --at 42` (head region). Commit "unk_575860: head includes ai.h (typing)", before 0891251.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64) - duplicate include
- `dcp headers conflicts f3gm unk_58bbd0.h --write` added a second `#include "unk_58bbd0.h"` at line 140 though the unit already included it at line 135, reporting `duplicate=0`. Second time today that `--write` ignores an existing include. Removed by hand.
