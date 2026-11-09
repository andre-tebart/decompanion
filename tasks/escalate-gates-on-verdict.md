# Escalate gates on the verdict, not on prose

- **Priority:** P1 · **Size:** S · **Root:** R1

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
  It does not check branches or switch tables, though `asmcmd::reading` holds them. (Reference and literal
  differences, the reference check's, refuse since that check landed: `rd.ref_lines` with `grade::code_grade`.)
- The printed size is `la.len() - tails` (queues.rs:741-742). The tail adjustment goes only into the stored reason.

## Task

- Refuse on any remaining *concrete* difference from the one verdict: witness, real branch differences, switch table
  entries (the references and literals already refuse). The real branch differences are `Verdict::branches` (the
  cut correspondence, `diffclass::Cuts`); `Verdict::into_code` lists the jumps a code hunk accounts for and is no
  difference of its own.
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

## Addendum (2026-11-09): re-check the deep queue

gildegold holds 1044 deep items, escalated under older and weaker gates. Once the gate refuses on the verdict
(and on reference-census's differences once that is a concrete difference), `dcp next --deep` marks each item whose
tag the gate would refuse now (`refused now: ...`). That gives a ranked list of meaning differences let through
before the deep pass starts.
