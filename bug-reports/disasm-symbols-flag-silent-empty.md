# `dcp disasm --symbols` possibly gives empty output with the error hidden (unverified)

- **Source:** match-base session 2026-11-02 (gildegold), worker 50
- **Severity:** minor (unverified: stderr was suppressed)
- **What happened:** `dcp disasm 0x582b40 --symbols 2>/dev/null | tail -n +3 > file` produced an empty file. Likely disasm rejects `--symbols` (which asmdiff accepts) and the error went to stderr.
- **Expected:** accept `--symbols` as a no-op on disasm (it already annotates symbols), or document the difference; an unknown flag should not yield an empty stdout that looks like success to a pipeline.
- **Repro:** `dcp disasm 0x582b40 --symbols` (check stderr).
- **Impact:** one retry.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55) - confirmed
- `dcp disasm 0x5890c0 --symbols` prints `dcp: invalid literal for int(): '--symbols'`: the flag is parsed as an address. So the earlier empty output was this error on stderr. Want a proper "unknown option" error (or accept `--symbols` as a no-op). Cost: one wasted call.
