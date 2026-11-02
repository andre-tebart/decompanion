# asmdiff/diffclass misalign a chain of near-identical blocks after a one-register difference

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Severity:** minor
- **What happened:** in sv_RefreshPanel, moving the `j == 0` block of the job-kind chain to the end (where the original has it) made codegen closer, yet distance went from 339 to 423 differing and diffclass reported large `code` hunks. One register difference in the case-0x61 body (ours `mov ecx, esi`, original `mov edx, esi`) made the aligner skip a whole ~40-line case and pair 0x43 with 0x62, 0x62 with 0x65, etc. `asmdiff --all` shows the original's `cmp cl, 0x43` at 0x529a51 opposite our `cmp cl, 0x43` at 0x529a74 with a full + block before it. After a later unrelated register shift the same function showed 118 differing and 4 code hunks.
- **Expected:** anchor alignment on compare constants and calls, or score a register-renamed instruction as a cheap match before insert/delete.
- **Repro:** at gildegold commit "sv: sv_RefreshPanel -> deep" (before 4dc46a1), replace `d2_WinOpenPicStyledS(` with `d2_WinOpenPicStyled(` in sv_RefreshPanel, then `uv run dcp asmdiff sv_RefreshPanel --all | grep -n "cmp cl, 0x"`.
- **Impact:** 15-20 minutes and a near-wrong revert of a correct change.
- **Related:** diffclass-rotation-with-reorder-as-code.md, ../improvement-reports/asmdiff-regs-auto.md
