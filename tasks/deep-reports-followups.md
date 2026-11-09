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

## Open

1. **diffclass-allocation-classed-code** (P1, M): byte sub-registers should follow the 32-bit renaming; a spilled
   against a register-held variable is `slots`/`regs`; a 3-operand `lea` against `add` + `lea` is an equivalent
   selection; pushes scheduled earlier with their instruction are `order` (sv_ScrollCamera). Repro: `dcp diffclass
   init_Betrieb`, `ls_ReadSceneRecords` at gildegold ce2b9146.
2. **asmdiff-moved-block-view** + the data half of false-m8 (P1, M): match basic blocks by content after renaming;
   `block at ours +X equals the original's +Y (moved)`; diffclass classes such hunks `order`; an M8 / M10 a moved
   block explains is `block order, not meaning` (sv_ScrollCamera's decay blocks, d3fl_MakeJitter's constants).
3. **wrap-unexplained-grade-change** (P1, S): say whether the baseline was stale (promoted before the last commit)
   or the object changed; name the edit behind a raise through a shared macro / header / inline helper.
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
