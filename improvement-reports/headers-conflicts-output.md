# `dcp headers conflicts`: summary first, and handle superseded K&R redeclarations

- **Source:** match-base session 2026-11-01 (gildegold), worker 13
- **Area:** `dcp headers conflicts`
- **Problem:**
  - with `--trial`, 137 per-function `fn=` lines come before the `trial=... falls=0` verdict and conflict kinds; the worker had to grep;
  - after `--write` with f3gm.h, the K&R `int gm_BuildingLevel();` in sv.c stayed (compatible redeclaration, not dropped) and kept its Q7 until removed by hand.
- **Proposal:** summary first (or `--quiet` dropping the `fn=` list); `--write` also drops K&R redeclarations the header's prototype supersedes, or lists them as "superseded K&R".
- **Cost of not having it:** one extra call; minor manual cleanup.
- **Related:** ../bug-reports/headers-conflicts-write-splits-address-comment.md, rename-summary-line-first.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 20)
- When sibling units already have a known `@original` cast macro for a `kind=call` conflict (main.c and unk_5d33b0.c use `d2_PlaceMainWindowF`), `--write` could insert or offer it.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 21)
- `headers conflicts` flagged the existing call `ai_StepShot()` as `kind=other` "too few arguments": a real meaning bug (missing argument). A distinct category ("call contradicts the header's prototype: likely a missing argument") would make it stand out. Positive: it caught the bug.

## Also seen (match-base session 2026-11-02 (gildegold), worker 24)
- `uv run dcp headers conflicts gv include/net.h` (no `--trial`) prints `regrade=0` and then ~60 `fn=... code=byte|shape` lines: the functions under the declaration-set warning, not ones needing a regrade; only `--trial` (`falls=0`) showed the include was safe. Proposal: title the block (`declaration-set: N functions, run --trial`) or fold it into the warning. Cost: 1 extra call plus reading.

## Also seen (match-base session 2026-11-02 (gildegold), worker 49) - output size
- `--trial` / `--write` still list every function to re-grade, ~110 lines, even when the verdict is `falls=0 rises=0 same=178`. Want after a trial only the count (`regrade: 105 functions, trial falls=0`), listing functions only when there are falls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- `dcp headers conflicts unk_575860 include/d2.h` printed ~160 lines: ~25 detail lines plus 138 `fn=... code=shape` regrade lines. Needed: the summary (supersedes=1, prototyped=10, duplicate=17), the one supersedes item and the regrade count. Want `regrade=138 (list: --list)`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- Long `fn=... code=shape` regrade list (worker took the last ~15). Want verdict first (compiles? blocking conflicts? regrade count), per-function list behind `--list`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- `dcp headers conflicts unk_575860 d2.h`: 3-4 lines per `prototyped` symbol (11) plus 17 duplicates, 30+ lines; needed only feasibility and blockers. Want a summary line (counts plus blocking `supersedes` entries) by default, detail behind `--all`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- Without `--trial`, ~250 `fn=0x... name=... code=shape|byte` lines; the conflicts scrolled away and `| tail` showed only fn lines. Want summary plus blocking kinds (`kind=call` / `kind=clash`), function list with `--list` or as `byte=73 shape=19`, `kind=prototyped` sites one line per symbol.
- Three runs per header (plain, `--trial` ~1-2 minutes on f3gm, `--write`). Want `--trial --write` that writes only when `falls=0`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- `dcp headers conflicts f3gm include/net.h`: all 117 byte/shape functions listed (~120 lines) though the trial said `falls=0`. Want the list only with `--list` or only for falling functions.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- `--trial` for rd.h: ~30 `fn=... code=shape` lines before `trial=... falls=0`. When `falls=0`, print counts only.
