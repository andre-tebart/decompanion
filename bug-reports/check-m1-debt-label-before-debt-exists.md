# `dcp check` labels a fresh M1 fall `debt` before any debt item exists

- **Source:** match-base session 2026-11-02 (gildegold), worker 50
- **Severity:** minor
- **What happened:** before `dcp debt add`, `dcp check` printed `error  debt  M1  0x00578e40 ai_TutorialInitChapter2 ... code byte -> shape`. The worker first read it as an existing debt item that had broken.
- **Expected:** a label such as `fall` or `needs-debt` for a fall with no debt entry; `debt` only for existing items.
- **Repro:** add a prototype to include/he.h that flips ai_TutorialInitChapter2, run `dcp check` (gildegold, after 0891251).
- **Impact:** small.
- **Related:** check-compile-failure-floods-m1.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- Again after a gv.h edit: `error  debt  M1  0x00578e40 ai_TutorialInitChapter2 ...` before any debt item existed. Want the category as a field, e.g. `error M1 (category=debt, uncovered)`.
