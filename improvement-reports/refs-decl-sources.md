# `dcp refs NAME --decl-sources`: which declaration each unit actually sees

- **Source:** match-base session 2026-11-02 (gildegold), worker 25
- **Area:** `dcp refs`
- **Problem:** before deleting a declaration from a header there's no way to see which units get the symbol only from that header; `dcp refs` lists declarations but not which one is in effect at each call, nor calls preceding any prototype (implicit declarations). Deleting gv.h's duplicate prototype of 0x4c4ac0 broke f3gm.c.
- **Proposal:** per unit, the declaration in effect at each call site (header + line, local K&R, or implicit).
- **Cost of not having it:** ~5 minutes plus a revert.
- **Related:** headers-signature-dry-run.md, stale-local-prototype-flag.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- Changing gm_QueryNext's return type set off an M5 with 12 disagreeing declarations, learned only from `dcp check`. Want a `dcp refs NAME --decls` count, or a hint in grade/build when definition and declarations diverge. Related: ../bug-reports/build-grade-miss-header-definition-mismatch.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 66)
- `dcp refs gm_PermissionBits` printed ~40 lines, mostly 25 `ref_to=call` sites; the worker needed definition and prototype sites to see what a signature change touches. Want `--decls`, or call sites as a count plus caller names on one line.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 67)
- Retyping gm_DropRank's parameter: `dcp refs` showed `ref_to=call ... fn_name=he_Unk55de30` but no declaration in he.c; grep confirmed the call has no prototype. Want per-caller `caller_decl=none|<file:line>`.
