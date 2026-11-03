# Signature claims from the original's call sites

- **Priority:** P2 · **Size:** M-L · **Depends on:** model-decisions (item 3)

## Problem

Workers read argument counts and widths from the original's pushes by hand. A wrong prototype shows up late, after
callers fail, although the original's call sites already say what the callee takes.

## Root cause

Types and signatures are not questions in the code yet (mental-model §10: "Types are questions: not yet"). No rule
derives a signature from I, so nothing can contradict a prototype early (§8.8).

## Task

- For each of the original's call sites, derive:
  - the argument count, from the pushes plus `add esp, N`, or the callee's `ret N`;
  - the widths, where a byte or word load is pushed without widening;
  - an `__int64` as a pair;
  - float bit patterns in int arguments;
  - whether the caller reads eax after calling a callee we declare `void`.
- Store these as derived claims on the signature question, with a contradiction against H's prototype (§8.8).
- Show them per call site in refs and in grade. Produce them where headers conflicts already reads "the original's
  pushes", so the logic is not duplicated.

## Rejected

- Hunk-text hints in asmdiff.
- "Which declaration each call sees" as a refs feature. That is H's build (clang / M5), better reported by lint.

## Reports

- refs-call-pushes
- asmdiff-param-type-mismatch-hint
- grade-call-arg-count-vs-definition
- lint-void-callee-result-used (part 1)
- refs-decl-sources (H side)
