# `dcp grade`: say when the object is unchanged since the last grade

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Area:** `dcp grade`
- **Problem:** three source spellings produced byte-identical objects, but only the summary line was printed, so the worker had to cat the file to confirm the edit had applied.
- **Proposal:** when the object hash is unchanged, print "object unchanged since last grade (hash ...)".
- **Cost of not having it:** ~5 minutes.
- **Related:** dcp-try-variants-in-memory.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 31)
- Swapping `util_RandomU(3)` for `util_Random(3)` in ai_DecideGraveyardOwner1 gave the same `dist` and hunks; the worker re-ran asmdiff to tell whether it recompiled (~2 minutes). Proposal additions: `dist was X -> now Y` against the previous grade of the same function in the session, and "object unchanged" after a rename-only rebuild.

## Also seen (match-base session 2026-11-02 (gildegold), worker 34)
- Three spellings of the 0.44 fvalue in ai_DecideUpgradeBusiness gave exactly `dist='65 ins / 261 bytes'`; the worker suspected a stale build and spent a call checking. "object for NAME unchanged by the edit" from build/grade would save 1-2 calls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 38)
- On ai_DecideUpgradeGuild and ai_DecidePriceManipulation several forms (nested if, negated condition, `goto set` / `goto none` / `goto buy`) gave identical objects, noticed only by comparing `dist` strings. A short object hash in `dcp grade` is most useful during layout and goto experiments. Cost: ~5 minutes.
