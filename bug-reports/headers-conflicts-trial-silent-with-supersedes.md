# `dcp headers conflicts --trial` gives no result while a `supersedes` conflict exists, without saying why

- **Source:** match-base session 2026-11-01 (gildegold), worker 11
- **Severity:** minor
- **What happened:** `uv run dcp headers conflicts sv gfx.h --trial` with 4 supersedes/vc6 conflicts (sv.c declares `d2_Objs` / `d2_LastWindowPtr` as `char *`, K&R prototypes) printed no `fall=` lines, so the cost of including the header was invisible.
- **Expected:** say "trial skipped: the unit does not compile with the include (N conflicts)", or run the trial with the superseded local declarations dropped automatically.
- **Repro:** the command above at gildegold 80355b6.
- **Impact:** small, but it is why the worker deferred the d2.h/gfx.h head question (which keeps Q4/Q7 open for every widget function in sv).
