# `dcp session wrap`: print a rename reason shared by several pairs once

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Area:** `dcp session wrap` (output size)
- **Problem:** for two-pair renames each long reason was printed twice, ~6 extra wide lines.
- **Proposal:** print a shared reason once and list its pairs under it.
- **Repro:** wrap at gildegold 0891251.
- **Cost of not having it:** context only.

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- Again: a wrap of ~30 lines printed the same long `why` twice for two renames from one call (gildegold 6853071).

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- ~40-line wrap; the renames section repeats every full why, the combined why twice. Proposal variant: renames as `old -> new` only, since the whys are in names.log (gildegold 1a594b8).

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- ~15 lines of ~400 characters (~6 KB): one `--why` shared by 10 renames printed 10 times. Want pairs grouped under one why, or the why cut at ~80 characters with `(names.log)`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- 5 identical multi-line whys, ~2 KB of the report. Want one line per rename (`old -> new  why=<first 80 chars>`) or a shared why printed once.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- ai_ClearBookmark and ai_ValidateBookmarks repeated one paragraph (65f9a10). Want `old -> new` per line, the why once per rename call or left to names.log.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- 18 rename lines, ten repeating one ~600-character why: ~12 KB, pushing the summary off-screen; the wrap was re-run with `| head` (728c0d8). Want one line per rename, a shared why once per batch truncated to ~100 characters with a pointer to names.log.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- One `--why` (~450 characters) repeated for each of 3 pairs (ca33582).

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- ~40-line wrap, ~25 of them renames because of the duplicated why. Want `OLD -> NEW` per line, why left in names.log.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- 14 renames x ~600 characters of shared why: ~9 KB; wrap ~40 lines, 90% repeated why. Want grouping: `why#1: ...` then `ai_Unk61a67c -> gm_QueryType [why#1]`, or whys truncated to ~100 characters.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- ~12 lines up to ~350 characters each: the full why repeated for 9 renames from one call. Want `9 renames (one batch): ai_Unk61a66c->gm_BQType, ... why: <text>`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- One ~300-character why printed four times for one multi-pair call. Want one why per call with its pairs under it.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- Three renames from one call repeated a 400-character why three times (~12 wrapped lines). Group and truncate.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66)
- A 3-pair rename gave three copies of a 400-character why (f30e72e).
