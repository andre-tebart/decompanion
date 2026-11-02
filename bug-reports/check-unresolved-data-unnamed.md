# `dcp check` reports `unresolved data=1` without naming the symbol; build doesn't warn

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Severity:** minor
- **What happened:** the worker declared `extern char ai_FmtInt[]` for 0x5fe7d0, which no definition covers. `dcp build` passed; only `dcp check` failed with `link:data=1` / `unresolved data=1`, no symbol name. Separately, disasm labelled 0x6f23c4 as `ai_Unk6f23c4` (from an `extern int` comment in sv.c) though the datum is the gap symbol `full_data_6f23c4`.
- **Expected:** `unresolved=ai_FmtInt` in check output; a build-time warning when a new extern names an address no definition covers; disasm prefers the defining symbol over a comment-only name.
- **Repro:** add `extern char ai_FmtInt[];` and a use in sv.c, `uv run dcp build`, `uv run dcp check` (gildegold 4dc46a1).
- **Impact:** ~5 minutes.
