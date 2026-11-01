# Classify "address taken vs value loaded" of the same symbol as a meaning hunk

- **Source:** play debugging session 2026-11-01 (gildegold)
- **Area:** dcp diffclass / dcp asmdiff / dcp lint (native/dcp_core/src/diffclass.rs)
- **Problem:** `ls.c` passed `ai_UpdateStart` (a scalar `int`) where the original passes its address:
  the original has `push 0xf89580` (an `immediate` ref) before `call ls_Read`; ours loaded the value from
  memory and pushed 0. `vfs_fread` skips a null buffer, so 0x18 bytes of every save were never consumed and
  every later reader was 24 bytes behind. The tutorial load then crashed in `ls_ReadCharacters` with a
  record id of 0x4d00. The hunk was in the diff all along, but `unk_Unk51c950` is at draft
  (221 differing instructions), so it looked like any other shape difference. The same mistake was at two
  more call sites (`ls_SaveGame` wrote from address 0, `ls_ReceiveGame`).
- **Proposal:** a diffclass class, e.g. `addrval`, for a hunk where both sides reference the same symbol but
  one takes its address (`push imm` / `mov reg, imm` / `lea`) and the other dereferences it (`push [sym]` /
  `mov reg, [sym]`). The original's ref facts already separate `immediate` from `operand`. Report it from
  `dcp grade` and `dcp check` as a warning at every grade, not only once a function reaches shape: it is
  almost never a shape difference. A project-wide `dcp lint` pass over all functions would have found all
  three `ai_UpdateStart` sites at once.
- **Repro:** gildegold commit 258ff9e, `src/ls.c:1428` (`LS_RD(ai_UpdateStart, 0x18)`), `:166`, `:2958`;
  `dcp asmdiff unk_Unk51c950`; `REA_START=tutorial dcp run play` crashes in `ls_ReadCharacters`.
- **Cost of not having it:** one crash that took a minidump, an offline parse of Tutorial.cty and a
  temporary position trace (about an hour). Related: `cast-hides-pointer-warnings.md`.
