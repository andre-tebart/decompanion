# A scoped edit for one function's body

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** dcp fn
- **Problem:** a scripted string replace on `float dx, dz, ex, ez;` also changed `rd_FillQuad`, which broke the build.
- **Proposal:** `dcp fn NAME --write FILE` (replace the body at the `at=` lines) and/or `dcp fn NAME --print-body`, so edits stay inside the function's line range.
- **Cost of not having it:** about 3 minutes.

## Also seen (match-base session 2026-11-01 (gildegold), worker 10)
- Twice a scripted whole-function replacement (definition up to `\n}\n`) lost the separating newline, hiding the next function's address comment (see ../bug-reports/grade-lost-address-comment-silent.md). Proposal: `dcp fn NAME --replace FILE` that swaps the function in place keeping the address comment and neighbours, and/or a build check that every address comment starts a line. Cost: ~5 minutes.

## Also seen (match-base session 2026-11-01 (gildegold), worker 11)
- Whole functions rewritten 5 times by splicing with python on the address comment and the closing brace line; a line offset shifted after one edit and only an assertion caught it. Same proposal: `dcp fn NAME --replace FILE` swapping address comment plus definition (the `at=` extent). Cost: ~10 minutes.

## Also seen (match-base session 2026-11-01 (gildegold), worker 12)
- Scripted edits hit the K&R head prototype instead of the definition (sv_UpdateSkyPhase, sv_FillDayPhases): a search for "void NAME(" matches the head first. Proposal: the skill says to use the `at=` range from `dcp fn`, or a script-friendly `dcp fn NAME --body-range`. Cost: two failed edits.

## Also seen (match-base session 2026-11-02 (gildegold), worker 16)
- sv.c is not in address order (0x52d010 comes after 0x52d2a0). A script cut from 0x52d010's comment to the next `/* 0x52d1e0,` comment, which lies above it: duplicated body, 3 C2084 errors, a `git checkout`, and a hand-redone rename (names.log already written). Proposal addition: `dcp fn NAME` prints `next_at=src/<unit>.c:LINE` (start of the next function's comment in file order). Cost: ~5 calls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 26)
- Replacing gv_WriteGraveyard by cutting from its address comment to the next higher address (0x4f2b30) deleted unk_Unk4f2da0, which sits between them because the end of gv.c is out of address order. `dcp check` caught it (M1 "no grade now (its source is gone?)", clear here) and the function was restored from HEAD. Address-based slicing is unsafe in out-of-order units; `--replace` should use the `at=` line range. Cost: ~3 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 34)
- A Python whole-function splice used an end marker that matched an inner `return 0x19;`, breaking the file (build caught it, failed=1). Same proposal: `dcp fn NAME --replace FILE` using the `at=` span. Cost: 2 calls.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 55)
- Every rewrite this session was a hand-made Python splice from the address comment to `\n}\n`; with heredoc backslash loss it broke one literal. Want `dcp fn NAME --replace FILE` reading the file as raw bytes: removes the most error-prone step of the loop.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- Splicing a new body up to the next `/* 0x` comment deleted a block of externs and macros (`G_MSG72`) between two functions; the unit failed with C2371. Want `dcp fn NAME --replace FILE` swapping exactly the address comment and definition, keeping what sits between functions. Cost: one failed build, ~4 calls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- Splicing by a stale `dcp fn ... at=FIRST-LAST` range after the line count changed left a stray `}` and broke the build. Want `dcp fn NAME --replace FILE`. Cost: ~4 calls, one broken build.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- Shell edits on the `dcp fn` range briefly broke the address-comment placement. Want `dcp fn --replace FILE` sized by the `at=` range.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- Every rewrite needed a Python cut by signature and the next `\n}\n`; the Edit tool is awkward when the function text isn't in context. ~1-2 minutes per function plus the risk of a bad cut.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- A PowerShell `IndexOf` splice matched the prototype at line 114 instead of the definition and duplicated ~420 lines into src/f3gm.c; unit failed to compile, restored with `git checkout`. `dcp fn` gives `at=src/<unit>.c:FIRST-LAST` but nothing writes to it. Want `dcp fn NAME --replace FILE` (or `--write` from stdin). Cost: one broken build, 2 recovery calls.

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- Worker spliced from gm_*'s prototype line instead of its definition, duplicating ~6000 lines of src/f3gm.c (restored with git checkout). Wants `dcp fn NAME --body` printing only the definition range for scripted replacement.
