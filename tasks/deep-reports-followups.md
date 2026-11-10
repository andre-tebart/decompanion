# The first deep-match sessions' reports: what is done, what is open

Source: bug-reports/ and improvement-reports/ of the gildegold deep-match sessions, 2026-11-09 (workers 1-4).

## Done (2026-11-09)

| Report | What changed |
|---|---|
| prover-tail-jmp-offset | equiv: a tail jump compares the callee-saved registers, stack and arguments; eax / ecx / edx are scratch (init_Betrieb proves, shape) |
| false-m8-from-misaligned-calls (calls) | refcheck::settle_calls: M8s at calls are dropped when both sides call the same callees in the same order |
| stuck-keeps-prior-reason | set_level keeps the earlier reason as `prior:` (once each, cut at 900 characters) |
| deep-queue-untagged-items | `dcp next --deep` prints `why=@deep|@stuck|untagged` |
| disasm-ours-placeholder-addresses | `disasm --ours` writes symbol+offset into the operand; an unknown flag is an error |
| variant-runner, fn-edit-by-name | `dcp try NAME FILE` (code hash, `= label` for identical code, `--move-line`, `--apply`) |
| frame-slot-map-command | `dcp frame NAME` |
| deep-match-skill | skills/dcp-match-deep, `session start --kind match-deep` |

## Done (2026-11-10)

| Report | What changed |
|---|---|
| arg-count-casts-hide-nested-call | equiv: a partial pop leaves an outer call's cells pending as its arguments; an FPU-argument call takes nothing from the stack. diffclass: reordered pushes / calls are code, code hunks are "moved" only when every call keeps its cleanup and every block its push order (stack_profile). The 14 functions the sweep fixed by hand are draft at gildegold 39bc1e2f; at 248c2969 ai_AttackWindow falls (a real bug: he_FindEvent's pair (id, 3) for (3, id)) and ai_MsgBuildingGetsItemType31 (a push hoisted above a branch; the prover stops at rep scasb: one false fall, for dcp debt add) |
| wrap-unexplained-grade-change | the cause window starts at the last promote, and each cause names the commits behind it |
| wrap-accepted-count-unexplained | promote prints `debt=N` with what it means |
| build-listing-command | `dcp listing NAME` (VC6 /FAc of the unit, as the build compiles it; DCP_KEEP_LISTING keeps the files) |
| frame-slot-map-command (names) | `dcp frame` names our slots from the listing's frame symbols (the base measured per function), follows ebp frames, saves interleaved with the first statement; the stack-depth walk no longer pops the saves at a stdcall call through a register (it drifted by 16 in lobby_ChoosePlayer) |
| asmdiff-hunk-to-source-line | `dcp asmdiff NAME --lines` |

## Open

1. **diffclass-allocation-classed-code** (P1, M): byte sub-registers should follow the 32-bit renaming; a spilled
   against a register-held variable is `slots`/`regs`; a 3-operand `lea` against `add` + `lea` is an equivalent
   selection; pushes scheduled earlier with their instruction are `order` (sv_ScrollCamera). Repro: `dcp diffclass
   init_Betrieb`, `ls_ReadSceneRecords` at gildegold ce2b9146.
2. **asmdiff-moved-block-view** + the data half of false-m8 (P1, M): match basic blocks by content after renaming;
   `block at ours +X equals the original's +Y (moved)`; diffclass classes such hunks `order`; an M8 / M10 a moved
   block explains is `block order, not meaning` (sv_ScrollCamera's decay blocks, d3fl_MakeJitter's constants).
3. (done 2026-11-10)
4. **asmdiff-regs-auto-misses-callee-saved-swap** (P2, S): vote over the prologue's push order and the body as one
   renaming of callee-saved registers; print `regs=ebx<->ebp`. Repro needs the di_UpdateButtons index-form variant
   (its `@stuck` tag): with `dcp try` it is one variants file now.
5. **census-folded-constant-hint** (P2, S-M): our literal = a·b, a/b, a+b, a-b of two constants the original loads:
   `VC6 folded two constants; split the statement`; an original operand in `.rdata` used by one unit only: `a
   static const?`.
6. **c2prio-referenced-but-missing** (P2, M-L): the VC6 register-priority measurement came from the REA toolchain
   and is not shipped; port it as `dcp prio NAME` or drop the reference from gildegold's notes/vc6-quick.md.
7. `dcp try` generators (P2, S each): swap the arms of an if/else, a for loop as a while loop and back.
8. `dcp frame` hint (P2, S): a frame 4 bytes short per vector: a 4-float vector type?
9. The e2e test `server_status_and_libs_candidates` expects LIBC.LIB placed=75 and gets 76 (fails on c692027 too):
   decide whether the placement changed for the better and update the expectation.
10. **diffclass-shifted-base-class** (P2, M): every displacement through one base register shifted by K (msx_Update:
    a loop pointer starting 8 bytes later): one class with its base, not 12 code hunks.
11. **deep-queue-sibling-grouping** (P2, S): `dcp next --deep` lists the unit's other deep items.
12. **stuck --amend** (P2, S): append to a tag's reason without rewriting it (the wrapped reason defeats a search
    and replace).
13. **m10-pooled-literals-noise** (P2, S-M): VC6's pooled float literals (ai_FloatOne / ai_FloatZero / cm_DoubleOne)
    open an M10 on every FPU function; imports open an M8 (recv, WSAGetLastError).
14. The stack-order rule's one false positive: a push hoisted above a branch whose arms both reach the call
    (ai_MsgBuildingGetsItemType31). Pushes per call across a diamond would settle it.
