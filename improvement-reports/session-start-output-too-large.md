# `dcp session start`: print the gate verdict and failures, not the full unit table

- **Source:** match-base session 2026-11-02 (gildegold), worker 50
- **Area:** `dcp session start` (output size)
- **Problem:** prints a full unit table (~92 unit lines) plus status blocks; the worker piped it through `tail -20`. Needed: the `gate:` line and any failures.
- **Proposal:** gate verdict and failing items by default; the units table behind `-v`.
- **Cost of not having it:** context only, every session.
- **Related:** session-start-garbled-sentence.md (bug-reports)

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- ~100 lines, mostly one line per unit (92), before the gate line. Needed: gate verdict and next item. Want `gate: ok`, obligations if any, a one-line unit summary (`units=92 separated=92`); per-unit lines only on failure or `-v`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- ~20 lines (units `separated`, toolchain, status block) before `gate:`. Want only the gate line and the queue head when the gate is clear.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- `dcp session start --kind match-base`: ~100 lines, one per unit (92), before the gate. Want the unit list only on failure or `--verbose`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- 25+ `unit=... range=... status=separated named_by=-` lines plus layout status. Want units listed only when not clean or open; at most 5 lines when the gate is ok.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- ~95-line unit table before the gate result; read with `tail -20`. Want `gate=ok units=92 open=0` plus the next item.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- ~25 lines, including details of the last three separated units (irrelevant to match-base). For `--kind match-base`, want the gate line and the first `dcp next` item.

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- 92 `unit=... range=... status=...` lines plus toolchain/status blocks; read with `tail -20`. Want gate verdict, open obligations, next item; unit list behind `--units`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- One line per unit (92) before the gate; want a one-line unit summary unless something is open.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- ~100 lines (92-unit list, toolchain/analyzer lines, status block). Want `gate=ok  target=exe  units=92 separated  next=0x00500970 gm_AddObjekt`, table behind `-v`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- ~20 lines before `gate: ok`. Want `gate=ok kind=match-base` plus the next item; unit status only with `--verbose` or on failure.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- ~25 lines; want one gate line plus the `dcp next` line, the rest behind `-v`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66)
- 15-20 lines of unit/layout/toolchain status before the gate. Want one `gate: ok` line plus one line per problem.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- Per-unit layout lines before the gate (probably ~100 lines with 92 units). For match-base want the gate result, the toolchain line and the first `dcp next` item; unit lines only when something is open.
