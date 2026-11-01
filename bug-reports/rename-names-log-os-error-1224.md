# `dcp rename` crashed on names.log (os error 1224) and left a half-done rename — FIXED

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Severity:** critical (fixed in decompanion 75d8781)
- **What happened:** `uv run dcp rename --from <file>` with 21 pairs crashed in `cmd_rename` → `native.core().rename_command` with `RuntimeError: …\names.log: … (os error 1224)`. All source files were already rewritten for all 21 pairs, but names.log got only the first 10 events. So the rename was not all-or-nothing.
- **Root cause:** `edit::log_names` rewrote all of names.log with `std::fs::write`, which truncates first. Windows refuses to truncate a file while another process has a section of it mapped (probably a short-lived git process; dcp itself maps nothing). Sources were written before the log, so a log failure left the tree half-renamed.
- **Fix (75d8781):**
  - names.log is append-only (`edit::append`, `log_names_each`).
  - `edit::write` / `write_bytes` write in place and retry errors 1224/32/33 with backoff for about 3 s.
  - `dcp rename` saves every target file first and puts all of them back if any write fails.
  - Tests: `test_rename_writes_all_or_nothing` and `edit::tests::write_in_place_and_append`.
- **Recovery used:** `git checkout -- .`, restart the daemon, re-run the rename.
