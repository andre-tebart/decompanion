# A unit file that can't be loaded (5M-line gv.c) silently disappears from the build

- **Source:** match-base session 2026-11-02 (gildegold), worker 29
- **Severity:** minor in this instance (caught), potentially serious (could be committed)
- **What happened:** a worker script's `str.replace('', new)` inflated src/gv.c by ~5.38M lines. `dcp build` showed no `FAILED` line and no error; the grade totals simply dropped (byte+readable 1601 -> 1536, shape+readable 100 -> 95). A rebuild printed `target=exe units=92 compiled=0 failed=0 fresh=92 removed=0 ms=16` (previously `units=93`). `dcp grade gv_FindAccused` said "is neither a unit nor a graded function of target exe"; `dcp fn gv_FindAccused` said "no function gv_FindAccused in the sources". `dcp serve --status` looked healthy (memory_mb=3317). `dcp check` was not run before the file was restored, so whether M1 would have caught ~100 missing functions is unverified.
- **Expected:** a unit file that can't be read/parsed (or exceeds a size limit) is an error: counted as failed, gate fails; the build warns when the unit count changes (`units 93 -> 92: src/gv.c not read (why)`); grade/fn say the unit file failed to load instead of "no such function"; optionally a loud warning on a sudden mass grade drop naming the units whose function count changed.
- **Repro:** make a unit file huge (e.g. insert text between every character), `uv run dcp build`, rebuild, `uv run dcp grade <fn in that unit>`, `uv run dcp check` (gildegold, before 3209111).
- **Impact:** ~3 minutes; would have been committed if the worker hadn't read the totals.
- **Related:** grade-lost-address-comment-silent.md, check-compile-failure-floods-m1.md
