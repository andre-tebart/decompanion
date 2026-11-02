# `dcp build`: show all compiler errors per unit (or a machine-readable list)

- **Source:** match-base session 2026-11-01 (gildegold), worker 7
- **Area:** `dcp build`
- **Problem:** am failed with `errors=89`, but only the first 10 were listed, so an error-driven fix loop needed many rounds.
- **Proposal:** `--all-errors`, or a machine-readable `file:line:code:msg` list per unit (e.g. `--errors-file`).
- **Repro:** rename `AIARG.unk04` in include/am.h, `uv run dcp build` (gildegold 37b970e).
- **Cost of not having it:** part of the ~15 minutes in rename-struct-field.md.

## Also seen (match-base session 2026-11-01 (gildegold), worker 8)
- Renaming `AIARG.unk10` -> `arg2` (~140 sites in src/am.c): `dcp build` printed only ~20 `C2039` lines per unit, and VC6 sometimes stopped at C1903 ("unable to recover") after one. About 50 build rounds over 3 loop runs; the largest single cost of the session (~10 min). Proposal additions: `--max-errors N`, or keep compiling past errors.
