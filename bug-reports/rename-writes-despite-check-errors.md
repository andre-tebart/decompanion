# `dcp rename` writes the rename although it prints check errors (new name already declared)

- **Source:** match-base session 2026-11-01 (gildegold), worker 3 (run by its subagent; exact error text not captured)
- **Severity:** minor (breaks the "refusal writes nothing" promise)
- **What happened:** `uv run dcp rename ai_Unk114fe60 txt_Random --why "..."` printed M6, M.compile and M1 errors, but still wrote the rename into every file and into names.log (line 189, 2026-11-01T10:41:29, 0x0114fe60). The skill says a refused rename is an `error=` record with exit 1 and nothing written.
- **Likely cause:** `txt.h` already declared `txt_Random` with a different array size than `io_text`'s `ai_Unk114fe60`. The rename created two disagreeing declarations of one symbol and probably a compile error, until the size was fixed by hand to `[0x4800]` in `io_text.h` and the definition.
- **Expected:** when the new name is already declared somewhere with another type, refuse before writing (exit non-zero, nothing written) and list the conflicting declarations.
- **Repro:** rename a placeholder to a name an included header already declares with a different array size.
- **Impact:** moderate; a manual fix of the size.
