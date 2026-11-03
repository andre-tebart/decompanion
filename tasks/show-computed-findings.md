# Show the findings that are already computed

- **Priority:** P1 · **Size:** S · **Root:** R5, R8
- **Related:** output-convention (the delta is where build shows them)

## Problem

M5, M6, N2 and D findings surface only at `dcp check`, after build said ok and grade said "consistency (M7) current".
Rename prints "1 from before" without naming the error. Workers learn the gate at commit time, and the skill adds
"run check before committing" to compensate.

## Root cause

- `build_target` lints the changed units (glue.rs:117-133, `lint_built`), so the findings are in the store. But
  `build_summary` (clicmd.rs:860-897) prints only compile errors and grades.
- `grade_command` (matchcmd.rs:102-148) and grade.rs:330-366 attach only M7 inside the function's span. The header line
  comes from matchcmd.rs:704-714.
- `rename_command` keys errors by (rule, addr, msg) before and after (rename.rs:408, 556-568). It names only the new
  ones and gives the old ones as a bare count.

## Task

- Build prints new and gone error findings, as part of the delta in output-convention.
- `grade NAME` lists the error findings inside its span (its definition, or a declaration of its name). It attaches M5
  and M6 next to M7, with the note reworded to "consistency (M5/M6/M7)".
- Rename names its existing errors (rule, location), not just a count.

## Rejected

- "Compare against HEAD or the session base" for rename: that needs a second build.
- The stale-objects theory in rename-zero-errors-on-stale-objects is wrong: `rename_after` already recompiles units that
  hold NEW (compile.rs:656-658).

## Model

§8.8: M5 and M6 are as much the consistency convention as M7.

## Reports

- build-grade-miss-header-definition-mismatch
- rename-from-before-counts-uncommitted-errors (7)
- rename-zero-errors-on-stale-objects
- stale-local-prototype-flag
- skill-m5-only-in-check
- grade-m7-current-wording
- check-original-marker-line-only (the M6 part)
- build-accepts-duplicate-function-name-across-units (the display part)
