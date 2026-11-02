# `dcp escalate --list [--unit U]`: past escalation reasons as reusable lessons

- **Source:** match-base session 2026-11-02 (gildegold), worker 35
- **Area:** `dcp escalate`
- **Problem:** fixes and dead ends (e.g. "assign the flags in each branch so VC6 doesn't fold to `sbb`", "nested ifs to one `return 0` give the shared exit") live only in commit messages and escalation reasons; no command lists them, so the next worker rediscovers them.
- **Proposal:** `dcp escalate --list --unit am` showing reasons (and maybe the shape-making commits' notes) for a unit or sibling group.
- **Cost of not having it:** none this session; repeated rediscovery later.
- **Related:** similar-function-hint.md, escalate-why-file.md
