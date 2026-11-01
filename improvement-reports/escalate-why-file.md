# `dcp escalate`: take the reason from a file or stdin

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp escalate
- **Problem:** the reason is a positional argument. Under PowerShell, a reason containing `\"` and `\` split into extra arguments. The command failed, and a chained `git add`/`commit` then ran with a broken message.
- **Proposal:** `--why-file FILE` (like `rename --from`) or read the reason from stdin.
- **Cost of not having it:** about 5 minutes and one retry.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 4)
- **Structured reasons:** escalation reasons get very long because they hold what was read, what was fixed, the remaining hunks and what was tried. Separate flags such as `--fixed`, `--left`, `--tried` (or a YAML file) would make the deep worker's input easier to parse.
