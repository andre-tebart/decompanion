# `asmdiff --changed`: show only differing lines with context

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** asmdiff
- **Problem:** the worker piped `dcp asmdiff` through `grep -v equal` most of the time.
- **Proposal:** `--changed`, which shows only differing lines plus a few lines of context.
- **Cost of not having it:** context only.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 49) - output size
- `dcp asmdiff ai_CannonExplosion` printed 741 lines; only the `code` hunks were needed. Want `--class code` (filter by diffclass class) or `--hunk 0xADDR` to print a single hunk. Related: asmdiff-window.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 50)
- 250-400 lines for 400+ instruction functions, paged in chunks; only the differing hunks were needed. Want `--only-diff` / `--context N`, also hiding `=` alias-only lines.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- Two legend lines per call; 300+ lines for ai_OpenItemTooltip (450 instructions) even after `grep -v "^   "`. Want `--changed` (only `-`/`+`/`!` with context), legend only with `-v`, and `--hide-alias` to drop `=` lines (string literal vs `full_data_` alias), a large share of ai_OpenCharTooltip's remaining lines.

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- `asmdiff --symbols` prints a 3-line legend on every call; want it once per session or behind `-v`. Overall the worker piped almost every dcp call through grep/tail/cut (~30 extra filters this session).

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- Default asmdiff good overall, but two `!` noise sources: every layout-shifted branch is `!`, drowning real callee/datum mismatches; and `--symbols` `=` alias lines for float constants (`_real@...` vs `0x5ee150`) when values agree. Want agreeing literal `=` lines dropped and shifted branches marked separately. Related: ../bug-reports/grade-branch-shift-noise.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- ~300 lines for gm_PartnerStep (asmdiff / diffclass `--all`), mostly register-rename-only lines. Want `--non-regs` hiding hunks diffclass explains as regs, slots or frame (would leave ~20 useful lines).

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- gm_InitBuildingTables (142 instructions): 200+ lines paged with sed, mostly regs/frame hunks. Want `--unexplained` (hide hunks diffclass explains as regs / frame).

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- gm_CreateObject (~490 instructions): the worker used `dcp diffclass --all` plus awk instead of asmdiff. Want `dcp diffclass NAME --code` printing only `code`/`tail`/`branch` hunks with their lines.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- gm_CreateBuilding: ~200 lines where register/slot noise and real differences look alike. Want runs differing only by register/slot renaming collapsed, e.g. `~ 12 lines, slots [ebp-0xc]<->[ebp-0x10]`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66)
- Hundreds of lines for gm_PermissionBits without `--changed`; mostly `--changed` or `--at` used. Want `--changed` as the default when the diff exceeds ~100 lines.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- `dcp asmdiff gm_TitlePeriodServed --symbols`: ~120 lines, about a third `=` alias lines like `fmul dword ptr [_real@41800000 (16.0)] | fmul dword ptr [0x5ebb18 (16.0)]`; filtered with `Select-String -NotMatch "^="`. Want `=` lines folded into the equal runs by default, `--show-aliases` to bring them back.
