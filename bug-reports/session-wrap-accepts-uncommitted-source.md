# session wrap grades from an uncommitted working tree without warning

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Severity:** minor
- **What happened:** a function commit failed (see improvement-reports/skill-windows-commit-message-file.md), leaving `src/main.c` edited but uncommitted. `dcp session wrap` said `head acf823a, 7 commits` but promoted main_OpenEngine to byte + readable from the working tree. The worker committed afterwards (3c1e30e, then baseline bfcf2ba), but the ledger and the commits could have drifted apart.
- **Expected:** wrap warns or refuses when `src/`, `include/` or `decl/` have uncommitted changes (other than its own `ledger/grades.tsv`).
- **Repro:** edit a function so it gains a grade, do not commit, run `uv run dcp session wrap`.
- **Impact:** about 3 minutes repairing the commit order; risk of a ledger not reproducible from history.
