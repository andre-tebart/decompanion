# The consistency convention covers uses

- **Priority:** P1 · **Size:** M · **Root:** R8
- **Related:** model-decisions (M7's status)

## Problem

- A `char *` passed for an `AIBLD *`, or an int for a pointer, goes unnoticed.
- Cast macros stay after a prototype is fixed (`gm_TitleJobI`, `I50A640`).
- Call-site casts around a `void` prototype stay.
- Stale `@original` views stay.

## Root cause

- clang runs with `-Wno-everything` plus only `-Wdeprecated-non-prototype` and `-Wimplicit-function-declaration`
  (frontend.rs:26-28). Int conversion and incompatible pointer types are only warnings in C89. So §8.8's "every use
  agreed with the declaration" is checked only for errors.
- Exceptions are text markers with no link to a symbol (exceptions.rs). An explicit function-type cast is invisible to
  the checker, marked or not.

## Task

- Enable `-Wint-conversion`, `-Wincompatible-pointer-types` and `-Wincompatible-function-pointer-types` as consistency
  findings at their call site, with `@original` and `@vc6` exemptions. Start them at warn, and list them per function in
  grade.
- An unmarked cast of a function designator to another function type is an inconsistent use.
- A marked cast whose type equals the current declaration does nothing: it is a stale exception, and `dcp exceptions`
  flags it.

## Rejected

- A gate list of VC6 warnings: that is the toolchain's noise (3897 warnings).
- A `headers signature` dry-run command: edit, then `dcp build`, lists the result once show-computed-findings is done.

## Model

- §8.8: the consistency convention.
- Exceptions go stale.
- Part of "an exception must discriminate", without a trial build.

## Reports

- cast-hides-pointer-warnings
- cast-views-on-prototype-change
- lint-void-callee-result-used
- lint-placeholder-cast-macros
- rename-retype-view
- headers-signature-dry-run
- rename-leaves-stale-macro-name (the stale `@original` comment)
