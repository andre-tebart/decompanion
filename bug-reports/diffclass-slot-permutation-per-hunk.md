# diffclass solves stack-slot permutations per hunk, labelling the continuation `code`

- **Source:** match-base session 2026-11-02 (gildegold), worker 28
- **Severity:** minor (shape function graded draft)
- **What happened:** gv_RankCulpritsAll (0x4f3dd0): 154 vs 154 instructions, every difference a stack-slot permutation plus one scheduling swap. The hunk at 0x4f3f43 is `slots` (`[+0x10]->[+0x18] [+0x18]->[+0x28] [+0x28]->[+0x10]`), but the next hunk at 0x4f3f79 is `code 36` though it continues the same permutation plus a 0x1c/0x20/0x24 rotation that the hunk at 0x4f3e86 already labelled `slots`. The hunk at 0x4f3e25 (`code 8`) is `xor edi,edi; mov [esp+0x1c/0x20],edi` moved around `mov esi, X` / `and eax,0xffff`: a slot rename plus a reorder. Verdict draft (B3 "code 44, slots 30"); escalated as draft + readable. Likely similar on gv_RankCulprits (0x4f3c50): a pure ecx -> ebp rename on `n++` that also moves the store, labelled `code 12`.
- **Expected:** one slot permutation applied across the whole function (or carried between hunks), and `order` + `slots` allowed together in one hunk.
- **Repro:** at gildegold 21f024d, `uv run dcp diffclass gv_RankCulpritsAll --all`, `uv run dcp asmdiff gv_RankCulpritsAll`.
- **Impact:** ~3 extra calls reading line by line; a shape function counted as an escalation.
- **Related:** diffclass-rotation-with-reorder-as-code.md, ../improvement-reports/asmdiff-regs-auto.md, ../improvement-reports/diffclass-arg-slot-reuse-class.md
