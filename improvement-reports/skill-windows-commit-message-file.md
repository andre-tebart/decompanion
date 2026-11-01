# dcp-match-base skill: safe multi-line commit messages on Windows

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** dcp-match-base skill (commit step)
- **Problem:** the skill shows only `git commit -m ...`. On Windows, a PowerShell here-string piped into `git commit -F -` passed the text as a pathspec and the commit failed, which led to bug-reports/session-wrap-accepts-uncommitted-source.md.
- **Proposal:** recommend writing the message to a scratch file and `git commit -F <file>`, or add a `dcp commit` helper that also appends the attribution lines.
- **Cost of not having it:** one failed commit plus the wrap ordering repair.
- **Related:** skill-edit-scripts-not-heredocs.md
