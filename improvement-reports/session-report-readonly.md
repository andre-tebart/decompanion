# `dcp session report`: reprint the session report without re-running wrap

- **Source:** match-base session 2026-11-01 (gildegold), worker 5
- **Area:** `dcp session wrap`
- **Problem:** running `dcp session wrap` a second time re-runs it and reprints the whole report, including all ~40 renames since session start. Harmless but noisy.
- **Proposal:** a read-only `dcp session report` (or make a repeated wrap print only what changed since the last wrap).
- **Repro:** `uv run dcp session wrap` twice at gildegold commit f47bfc6.
- **Cost of not having it:** minor; output noise.

## Also seen (match-base session 2026-11-02 (gildegold), worker 15)
- A second `dcp session wrap` (to re-read the report head) re-ran the whole wrap without warning; its output then listed grade changes and renames already promoted. Proposal: `--report`, or a notice that a wrap for this base already exists.

## Also seen (match-base session 2026-11-02 (gildegold), worker 32)
- The wrap's head (byte/readable before -> after) scrolled away behind the renames list; the worker re-ran `dcp session wrap` just to read it, worried about double-promoting the baseline. Proposal addition: repeat the summary lines at the end of the wrap output.
