# Dry-run a prototype change: list callers and the argument types they pass

- **Source:** match-base session 2026-11-01 (gildegold), worker 9
- **Area:** `dcp headers` / `dcp refs`
- **Problem:** five times a callback's parameters changed from `unsigned char *` to `AIARG *` in `include/unk_4a7140.h`; each time the worker ran `dcp refs` and read the call sites in src/am.c to confirm they already passed `AIARG`.
- **Proposal:** `dcp headers signature NAME "new prototype"` (dry run) listing each caller with the type of every argument it passes, flagging those that would need a cast or would change code.
- **Cost of not having it:** ~1 minute per function, 5 functions.
- **Related:** build-list-grade-changes.md

## Also suggested (match-base session 2026-11-01 (gildegold), worker 10)
- Return-type change across implicit-int callers: ~8 units called gm_TitleJob with no prototype and am.c had a conflicting `int` prototype. Giving f3gm.h `unsigned char gm_TitleJob(int, int)` took add, build, read C2371, read the M1 list, then an `@original` cast macro (`gm_TitleJobI`) per unit whose callers read an int. Proposal: `dcp headers declare f3gm.h "unsigned char gm_TitleJob(int, int)" --trial` listing units that break, functions whose grade would fall, and implicit-int callers whose bytes read the result as int (suggesting the cast macro). Cost: ~8 minutes, four build/check rounds.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 25)
- Three signature changes this session (`cm_SendFloatDelta` int -> float parameter, every caller pushes via `fstp`; `cm_SendRelations` void -> int return; `gv_LeasePrice` care argument -> unsigned char, plus a redundant K&R declaration in unk_575860.c) all went by build-and-fix rounds. Same proposal as `dcp sig trial NAME "new prototype"`: compile every affected unit, list M5/M6 conflicts and grade falls without writing. Cost: ~10 minutes over three changes.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 33)
- `gm_GetJobTalents` typing (returns a 6-byte `JOBTALENTS` by value; new include/f3gm_types.h) touched 7 files; the worker worked out by hand which callers' grades could drop. The preview should list the callee's call sites with their grades (all units), not just same-unit functions. Cost: ~5 minutes.
