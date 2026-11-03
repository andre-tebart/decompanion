# Compile diagnostics as individual findings

- **Priority:** P2 · **Size:** M

## Problem

Build shows at most 10 compile errors per unit. Failed units compiled in the same build get their errors printed
twice.

## Root cause

- Both compile.rs:348 and clicmd.rs:878 take 10. The store keeps every diagnostic (`tu.diags`).
- VC6 itself stops at C1903, and no flag fixes that. The clang lint runs with `-ferror-limit=0` (frontend.rs:27) and
  lists every site.

## Task

- Each compile diagnostic becomes an individual M.compile finding with file:line. All of them are listed by
  `dcp findings` or `-v`, under output-convention; each is listed once.
- When a unit fails to compile, also surface the lint's errors for it.

## Rejected

`--all-errors`, `--errors-file`.

## Reports

- build-all-errors
