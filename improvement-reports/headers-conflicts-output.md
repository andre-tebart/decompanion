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
