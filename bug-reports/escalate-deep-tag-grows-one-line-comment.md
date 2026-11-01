# `dcp escalate` keeps appending the `@deep` text to one line of the address comment

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Severity:** minor (readability)
- **What happened:** each escalation adds its tag at the end of the address comment. In `txt.c` this has produced one huge single-line comment.
- **Expected:** wrap the comment, or replace the previous `@deep` reason instead of appending.
