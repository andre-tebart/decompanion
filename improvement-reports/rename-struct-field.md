# `dcp rename-field STRUCT.field NEW`: typed struct field renames

- **Source:** match-base session 2026-11-01 (gildegold), worker 7
- **Area:** `dcp rename` (new subcommand)
- **Problem:** renaming `AIARG.unk04` -> `ref` and `.unk08` -> `arg` (about 350 uses in am.c) had no tool; `dcp rename` covers only functions and data. Workaround: rename in the header, loop `dcp build`, parse `C2039 'unk04' is not a member of 'AIARG'`, sed the word on those lines. Lines like `u.unk04 = s2->unk04;` where `u` is another struct (AIUSE / G8USE) with its own `unk04` got wrongly renamed and needed hand fixes.
- **Proposal:** `dcp rename-field AIARG.unk04 ref --why ...`, driven by clang's typed references (lint already runs clang), with the usual byte-neutral check and a names.log entry.
- **Repro:** rename a field of AIARG in include/am.h at gildegold 37b970e.
- **Cost of not having it:** about 15 minutes and roughly 30 builds; the biggest friction of the session.
- **Related:** build-all-errors.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 8)
- `AIARG.unk10` -> `arg2` (~140 lines of src/am.c) via the same build-parse-sed loop; blind line-based sed risked hitting an unrelated `unk10` on the same line.
- The skill covers function/data renames and says "locals and parameters: edit the function", but nothing about struct members, though Q2 often flags fields (`unk10`, `unk194`, `unkac`). Proposal addition: at least a `dcp refs STRUCT.field` listing member accesses by type (grep `->unk10` hits many unrelated structs), plus a skill line on field renames. Cost: ~5 minutes working out affected uses, on top of the build loop.

## Also seen (match-base session 2026-11-01 (gildegold), worker 10)
- AIARG.unk0c -> ref2 via the error loop broke am.c:8863 `m.unk0c = s1->ref2;` where `m` is a G8MSG. A type-aware rename must only touch accesses whose base expression has the target type. Cost: one extra build round.
