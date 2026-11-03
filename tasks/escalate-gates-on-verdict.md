# Escalate gates on the verdict, not on prose

- **Priority:** P1 · **Size:** S · **Root:** R1
- **Depends on:** branch-targets-as-cut-points (otherwise escalate refuses on false positives), ref-check-in-object-experiment

## Problem

- Escalate accepts functions with real "branch targets differ" lines, or with code hunks the reason calls "allocation
  only" (8 sightings).
- Its refusal quotes instruction counts that differ from the asmdiff header (559 vs 544).
- Workers type reasons by hand that the tool could state, and the prose regexes reject them.

## Root cause

- `level_command` (queues.rs:735-765) checks only three things:
  - the size rule;
  - `equiv::witness`;
  - two prose regexes (`only_missing_statements`, `admits_unread`).
  It does not check branches, literals or switch tables, though `asmcmd::reading` holds all of them.
- The printed size is `la.len() - tails` (queues.rs:741-742). The tail adjustment goes only into the stored reason.

## Task

- Refuse on any remaining *concrete* difference from the one verdict: witness, real branch differences, literal
  mismatches, switch table entries.
- Each is explained only through the existing `--divergence-explained`.
- The refusal prints the diffclass summary and the raw counts: "ours 544, +15 for shared tails = 559, limit 12".
- `only_missing_statements` names the clause it matched, as `admits_unread` already does.
- The reason can come from a file or stdin (`--why-file F` or `-`). Echo the file:line of the tag, and append the
  remaining hunk summary to the stored reason.

## Rejected

- A "code hunks above half" ratio: a heuristic that would block valid deep items.
- `--check` dry run: a refused escalate already writes nothing.
- `--amend`: re-escalating already replaces the reason.
- Structured `--fixed/--left/--tried` flags.
- `@blocked`: use debt's `--waits-for`.

## Reports

- escalate-refuse-branch-targets-differ (8)
- escalate-instruction-count-differs-from-asmdiff
- escalate-list-forbidden-phrases
- escalate-why-file
- grade-show-instruction-counts (threshold part)
- skill-shape-vs-escalate-guidance (tool part)
