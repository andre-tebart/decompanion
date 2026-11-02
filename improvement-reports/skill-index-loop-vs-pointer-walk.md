# Skill/diffclass: `jl` against an address means an int index loop, `jb` a pointer walk

- **Source:** match-base session 2026-11-01 (gildegold), worker 6
- **Area:** dcp-match-base skill, `dcp diffclass`
- **Problem:** the original ends loops with `cmp reg, <address>; jl` (signed compare against a pointer). In VC6 that comes from an int index loop that was strength-reduced (`for (k = 0; k < 24; k += 4) ... deck[k+i]`), not from a pointer walk. The skill says "a cmp reg, <address> loop end is an array of structs walked to its end", which steers toward pointers: the wrong half for the signed case.
- **Proposal:** add to the skill "jl/jge against an address = int index loop; jb/jae = pointer walk"; or diffclass flags `jb` vs `jl` mismatches on a loop end against an address.
- **Repro:** ai_PokerFindPair / ai_PokerDrawCard in unk_4a7140 (gildegold 2fb619b).
- **Cost of not having it:** about 10 minutes on the first function; the insight then fixed 4 functions.
- **Related:** diffclass-idiom-hints.md, vc6-optimizer-hints.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 12)
- Four more times in unit sv: `jl` vs `jb` on a pointer-compare loop end meant a signed index loop over an array in the original. Proposal: a diffclass note on exactly that hunk.

## Also seen (match-base session 2026-11-02 (gildegold), worker 21)
- gv_ReserveEffect: rewriting an int-pointer slot walk as `GVEFFECT *e; e < gv_EffectsT + 8` gave `jb`; the original's `(int)p < (int)end` gives `jl`, so the readable version lost byte and was reverted. Hint wanted when the only diff is `jb` vs `jl` on a loop-end compare: "the original compares pointers as signed ints".
