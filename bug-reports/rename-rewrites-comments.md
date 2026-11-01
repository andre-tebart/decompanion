# `dcp rename` also rewrites the old name inside comments

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Severity:** minor
- **What happened:** the whole-word replacement changed the old name inside `txt.c`'s `@deep` note. That note argued from the fact that one object had two names (`ai_Unk114fe60` vs `txt_Random`), and after the rename it read "txt_Random ... txt_Random". It was rewritten by hand in gildegold commit ff7f657.
- **Expected:** an option to leave comments alone, or the rename lists the replacements it made inside comments so they can be reviewed.
- **Impact:** small, but easy to miss.
