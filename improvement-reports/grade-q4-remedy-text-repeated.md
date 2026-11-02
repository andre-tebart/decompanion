# `dcp grade`: the Q4 line repeats ~350 characters of remedy text on every failure

- **Source:** match-base session 2026-11-02 (gildegold), worker 53
- **Area:** `dcp grade` (output size)
- **Problem:** each Q4 failure prints the view-macro remedy text (~350 characters) every time; the worker needed only e.g. `Q4 raw access: 33 x *(T *), macro U_I`.
- **Proposal:** a compact Q4 line (count, form, suggested macro); the remedy once per session or with `-v`.
- **Cost of not having it:** context only, on every grade of a raw-access function.
- **Related:** q4-indexed-view-macro.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- Again ~400 characters of Q4 guidance (views, `&datum`, array forms) per call; B1 also repeats its "first differing byte / continues after our end" text. Want `Q4 raw access: 2 x *(T *) (lines 10116, 10166)` and `dcp grade --explain Q4` (or the skill) for the guidance.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- ~4 lines of the same Q4 advice per call; want the count plus a pointer to `-h`, or the hint once per session.

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- ~400 characters each time; want "Q4: N x raw access", the hint on first sight or via `--explain Q4`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- Repeated for every function in `dcp grade UNIT` too, so `dcp grade f3gm` would be hundreds of lines.
