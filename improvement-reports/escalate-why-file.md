# `dcp escalate`: take the reason from a file or stdin

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp escalate
- **Problem:** the reason is a positional argument. Under PowerShell, a reason containing `\"` and `\` split into extra arguments. The command failed, and a chained `git add`/`commit` then ran with a broken message.
- **Proposal:** `--why-file FILE` (like `rename --from`) or read the reason from stdin.
- **Cost of not having it:** about 5 minutes and one retry.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 4)
- **Structured reasons:** escalation reasons get very long because they hold what was read, what was fixed, the remaining hunks and what was tried. Separate flags such as `--fixed`, `--left`, `--tried` (or a YAML file) would make the deep worker's input easier to parse.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 5)
- The reason has to list the remaining hunks by address, which the worker copied by hand. Proposal: `dcp escalate --auto-hunks`, which appends the remaining non-shape hunks (address + class) to the reason.

## Also seen (match-base session 2026-11-01 (gildegold), worker 9)
- In PowerShell, a reason with escaped double quotes (`sprintf(name, \"prva_...\")`) inside a double-quoted argument was split into several arguments; argparse failed with `dcp: error: unrecognized arguments: prva_...` and nothing was recorded. Repro: `uv run dcp escalate ai_CheckVisitAction "each case is sprintf(name, \"prva_...\") ..."`. Proposal: `--why-file FILE`, or a skill note to use single quotes and avoid inner double quotes. Cost: 1-2 minutes. Related: skill-windows-commit-message-file.md

## Also suggested (match-base session 2026-11-01 (gildegold), worker 14)
- `dcp escalate NAME --draft-reason` pre-filling the remaining hunks with their classes and addresses, so the worker only adds what was tried (same need as `--auto-hunks` above).
