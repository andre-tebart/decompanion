# One reference check in the object experiment

- **Priority:** P0 · **Size:** M · **Root:** R2, R1 (docs/report-triage.md)
- **Blocks:** escalate-gates-on-verdict, diffclass-meaning-classes, pooled-literal-owner

## Problem

The object experiment masks relocated fields, but only some places check where those fields point:

- Two swapped loads (`v1a4`/`v1a0`) grade `byte`.
- A wrong literal stays hidden while other hunks remain.
- asmdiff prints a different address behind an `X` field as an equal line.

## Root cause

- `byte` is M.match (masked bytes) plus `constant_mismatches`, nothing else (grade.rs:242-249).
- The φ check is M8 `m8_reloc` (rules.rs:459-505). It runs only for byte-matched or DLL-aid functions (rules.rs:464),
  and its result never reaches G.grade.
- Shape and the prover read every relocated field and every in-image number as `X` (x86.rs:111-127).
- `equiv::bind` *learns* each symbol's address from the original's aligned site. It uses φ only for symbols that no
  site binds (equiv.rs:2299-2340). That is the reverse of §8.4.
- The literal check runs only on `shape || proof` (grade.rs:155), so drafts never show M9/M10.
- A literal binds wherever the original's operand holds the same bytes, whatever owns that address
  (equiv.rs:2277-2283, 2305).
- asmdiff computes field identity only with `--symbols` (asmcmd.rs:349). `differing=` counts X texts
  (matchcmd.rs:217-218).
- Escalate ignores `rd.literals` (queues.rs:735-765).

## Task

Write one routine and run it for every compiled function: byte, shape, prover and draft alike.

- For each of our relocations whose site lines up with the original (through the shared alignment), compare the
  original's target with φ(our symbol):
  - equal: a reproduced ref claim;
  - different: failing (draft), reported as a concrete difference that names both targets;
  - φ undefined: open and listed, never learned silently.
- A literal is the same check, with its bytes as the target. A literal must not bind to an original target that φ
  names as a datum.
- `bind` checks against φ wherever φ is defined.
- Grade, asmdiff, diffclass and escalate read this result:
  - asmdiff shows it in the default view, counts it in the header, and prints `literal:` lines;
  - M8.reloc becomes the findings view of this result, not a separate rule.
- Read commands must stay within the warm budget. Names is already built for reads.

## Rejected

- "Grade should print the M8 line": that keeps two computations.
- `--symbols` stays a display choice only.

## Model

- §4: an experiment may mask a relocated value only together with the check that the field points to φ(target).
- §8.4: φ undefined is open, not failed.

## Reports

- grade-byte-misses-swapped-relocations
- grade-m9-hidden-while-other-hunks
- asmdiff-reloc-vs-immediate-equal (part 1)
- asmdiff-symbols-float-constant-value-missing (residual)
- txt-views-index-spelling (worker 53)
- lint-string-literal-bytes-vs-original
- const-datum-vs-literal-hint
