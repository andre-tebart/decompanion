# Readability coverage (Q2, Q4, lint hints)

- **Priority:** P2 · **Size:** S-M

Outside the model (§9). These are cheap once consistency-at-uses has enabled more clang warnings.

## Task

- **Q2:** `dcp grade NAME` prints the full Q2 list, labelled by kind (callee placeholder, field, local), without a new
  `--all` flag. Today it is cut at 8 (readability.rs:357-361). Add a union-alias hint. Macro names that spell an
  address count as placeholders.
- **Q4:** count `(char *)&obj + N`; today only the `*(T *)` regex and raw macros count (readability.rs:374-383). The
  message mentions the struct-array view.
- **Lint hints:** `-Wtautological-constant-out-of-range-compare`, `-Wunknown-escape-sequence`, and a duplicated
  identical address comment under Q6.

## Reports

- grade-q2-full-list
- grade-q2-ignores-union-alias
- per-kind-union-views
- grade-q4-misses-struct-plus-offset
- q4-indexed-view-macro
- lint-always-false-compare
- lint-duplicate-address-comment
- lint-placeholder-cast-macros (Q2 naming part)
- next-placeholder-callees
