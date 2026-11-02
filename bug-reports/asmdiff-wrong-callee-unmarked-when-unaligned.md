# A wrong callee goes unmarked when the call lines don't align (only a -/+ pair)

- **Source:** match-base session 2026-11-02 (gildegold), worker 21
- **Severity:** minor (hides real meaning bugs)
- **What happened:** in `unk_Unk4eeb70` (now gv_FireShots) ours called `cm_SendMoneyDelta` (0x4c5f60), the original `gm_SendMoneyDelta` (0x50cc50). The calls sit in hunks with differing registers, so asmdiff shows `-  0x004eec34  call cm_SendMoneyDelta` far from `+  0x004eec35  call gm_SendMoneyDelta`, no `!`; grade/diffclass count it as one more `code` line among ~200. Found only by reading `dcp disasm`.
- **Expected:** compare call targets as a multiset independent of alignment, e.g. a grade line `calls: ours cm_SendMoneyDelta x3, original gm_SendMoneyDelta x3` and a `C.callee` finding.
- **Repro:** at gildegold 9aad298 (parent of 9733dce), `uv run dcp asmdiff unk_Unk4eeb70 --symbols`.
- **Impact:** ~5 minutes and nearly missed; a silent meaning bug.
- **Related:** asmdiff-symbols-wrong-library-callee.md, asmdiff-misaligns-repeated-cases.md
