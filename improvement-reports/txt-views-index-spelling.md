# Suggest `txt_Ptrs[index]` spelling for txt_views.h placeholder views

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Area:** mk_txt_views.py / lint
- **Problem:** txt_views.h exposes views like `full_data_143b3f8` (`unsigned char[12]` at +0x1238) whose meaning is `txt_Ptrs[0x48e + kind*14]`; Q2 flags them as placeholders. Writing `txt_Ptrs[...]` compiles identically (shown as `=` aliases in asmdiff).
- **Proposal:** mk_txt_views.py comments each view with its `txt_Ptrs` index, or a lint hint suggests the `txt_Ptrs[index]` spelling.
- **Cost of not having it:** ~5 minutes to discover.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 49)
- `dcp why 0x144a338` says `view=txt_Ptrs`, but the index (`(0x144a338 - 0x143a1c0)/4 = 0x405e`) had to be computed by hand for ~30 addresses. Want `= txt_Ptrs[0x405e]` in `dcp why` and `asmdiff --symbols`. Related: text-id-lookup.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- `full_data_144a620`, `_144a624`, `_144a638`, `_144a63c`, `_144a40c` are gap symbols inside txt_Ptrs (0x143a1c0..0x144c1b9) = `txt_Ptrs[0x4118]`, `[0x4119]`, `[0x411e]`, `[0x411f]`, `[0x4093]`. `dcp refs 0x144a620` shows only the gap name; indices computed by hand (~3 minutes over 3 functions). Want `dcp refs` / `dcp why` to say "inside txt_Ptrs: element 0x4118". See also check-gap-block-inside-known-object.md (bug-reports).

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- `full_data_144a498` and `full_data_144a4bc..4d8` are `txt_Ptrs[0x40b6]` and `txt_Ptrs[0x40bf..0x40c6]`; `asmdiff --symbols` only hinted (`txt_Ptrs+0x102d8` on our side) and Q2 lists them as placeholders. Want grade and asmdiff to say `full_data_144a498 = txt_Ptrs[0x40b6]`. Cost: ~3 minutes of offset arithmetic per function.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53) - silent meaning error
- `full_data_144a414`, `full_data_144a40c` etc. (txt_views.h: `txt_Ptrs + 0x10354`). The worker first typed three wrong indices from memory (0x4005, 0x4083, 0x408a); `dcp grade` still said readable, only a self re-check caught it. Want Q2 / `dcp why` / `asmdiff --symbols` to print `= txt_Ptrs[0x40d5]`, and M9 or the shape check to compare the index like a literal.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- Four more hand computations (`txt_Ptrs[0x205d]` from `full_data_1442334` / `0x1442368`) in `dcp disasm` output.
