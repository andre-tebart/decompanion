# diffclass hints for recognisable compiler idioms

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** diffclass
- **Proposals:**
  - **`?:` with two constants:** the `neg/sbb/and C/add B` idiom for `cond ? A : B` shows up as `code` hunks. A hint such as "looks like `x ? B+C : B`" would help. Cost: about 5 minutes to recognise.
  - **A char compare that can never be true:** `mov al,[..]; cmp eax,-0x21` is an `unsigned char` compared with the char constant `'\xdf'` (always false), which revealed the record pointer type. A hint such as "signedness: unsigned byte vs signed char constant" would help. Cost: about 5 minutes; very useful once understood.
- Related: vc6-optimizer-hints.md

## Also suggested (match-base session 2026-11-01 (gildegold), worker 9)
- **x87 compare form:** the flag test after `fnstsw` (`test ah,5; jp` vs `and eax,0x100; je|jne`) depends on how the C comparison is written. ai_DecideCharPair became byte-identical with `if (!(x >= 1.0f)) return 0;` instead of `if (x < 1.0f)`; ai_TrustedOfTwo matched with `if (A > B) *k = 1; else *k = 2;` instead of `if (A <= B) ...`. Proposal: when the only hunk difference is the post-`fnstsw` test, name it ("fpu compare form: original's `test ah,5; jp` comes from `!(a >= b)` / `a > b`"), plus a table in the skill. Cost: ~5 minutes of trial builds per function, 2 functions.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 11)
- **Hoisted common branch prefix / deferred pops:** VC6 hoists pushes common to both branches (`push 0` / `push pos` before `jne`) and defers stack pops. Sometimes the source fix is real (if/else with a duplicated call made sv_IsAtDoor byte; evaluating `GetPic` before the pushes needed a temp), sometimes it's allocation. Hint wanted: "common branch prefix hoisted (pushes before jcc)" pointing at "write the call in both branches".
- **Dead lea:** when the original materialises a pointer it never loads through, writing `ch = &ai_CharsT[c]` and reading `ch->field` at each use reproduces it (made sv_AddGroupMember byte; deep sv_RemoveGroupMember 0x524160 likely has the same fix). Worth a skill note.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 12)
- **FPU compare relation:** in sv_EaseCameraHeight / sv_UpdateSkyPhase the remaining hunks were `test ah,5; jnp` vs `and eax,0x100; jne`, and `and eax,0x4100; je` vs `test ah,0x41; jp`. Matching forms: `x < c ? x : c` and `fabs(..) > 0.2` (not `0.2 < fabs(..)`). Proposal: annotate each side's tested C relation and whether the branch is taken on true/false ("original: jump when st < m"). Cost: ~6 rebuilds.
- **Operand width:** `fmul dword ptr [const]` vs our `fmul qword` meant a float variable; `fsub dword [1.0f]` meant a `1.0f` literal. Hint: "operand width dword vs qword: expression is float on the original side".

## Also suggested (match-base session 2026-11-02 (gildegold), worker 19)
- **Unary minus and float multiply:** in sv_UpdateWeather `-wx * c * 2.0` compiled as `fmul; fchs`, the original has `fld wx; fchs; fmul st(1)`; only `-wx * (double)c * 2.0` reproduced it (~5 builds). Skill line (2.2): VC6 sinks a unary minus past a float multiply unless the other operand is double, so `fchs` before `fmul st(1)` points to a `(double)` operand.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 21)
- **Constant product folding:** `(int)(500.0f * a * 32.0f)` compiles to one fmul by 16000; the original has two (500, then 32). `32` / `32.0` didn't help (32.0 gave a qword constant); only a temporary (`v = 500.0f * a; (int)(v * 32.0f)`) matched. Hint: "constants folded: split the product through a temporary". Cost: 4 cycles.
- **Clamp idiom:** nested if / ternary / if-else-if produced `setle / dec / and` or misplaced the out-of-range block; only `max(min(x, hi), lo)` (windows.h) matched byte for byte in gv_SalvoCharge and gv_CannonKind. Hint when ours has a `setcc/dec/and` run where the original has a far `cmp hi / jge` block then `test / jg`. Cost: ~8 minutes first time.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 24)
- **Equivalent loop forms, same distance:** for gv_MoveGrave two loop forms gave the same `dist='82 ins / 376 bytes'`; only the copy inside a `for` loop with `break` reached byte, found by try order (~4 builds). Hint wanted: "the original keeps a redundant compare after the block, so the source probably tests inside the loop".

## Also suggested (match-base session 2026-11-02 (gildegold), worker 25)
- **Dead store kept in the original:** gv_RaiseDead's original keeps `mov word ptr [esi], 0xffff`, later overwritten; ours dropped it because both stores went through `c->id`. Writing the first through `gv_CharsT[slot].id` brought it back. Hint wanted when the original has a store overwritten later in the same block and ours has none: "dead store kept: write it through a different lvalue". `ahm_CreateAlchemist` (@deep) has the same missing-store gap and might be unblocked by it. Repro: `uv run dcp asmdiff gv_RaiseDead` before gildegold 5211788. Cost: ~5 minutes.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 27)
- **Return variable held in a callee-saved register:** the original keeps 1 in esi (`mov esi, 1 ... mov eax, esi` before each return), meaning `ok = 1; switch {... break; default: ...; ok = 0;} return ok;` rather than `return 1;` per case. Fixed gv_CrimeTextLaw2to8, gv_CrimeTextLaw9to16 and gv_TableRecordText. Hint wanted when a callee-saved register loaded with an immediate is moved to eax at every return. Cost: ~5 minutes.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 29)
- **Unsigned zero test:** the original's `test eax, eax / jbe` (unsigned `<= 0`, i.e. `x > 0` on an unsigned field) showed only as `code`/`branch`. A note "the original compares this unsigned (jbe) where ours compares signed / for equality" would have led straight to making `CRIME.state` unsigned. Cost: ~5 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 34)
- FPU compare form again: ~6 builds across ai_DecideBuildResidence and ai_DecideUseMilitaryObject learning that VC6 emits `test ah,5 / jp|jnp` for source `<` and `and eax,0x100 / je` for `>=`. Cheap to detect when diffclass pairs the two fnstsw sequences: "fcomp tested as `<` in the original, `>=` in ours (swap operator / branch sense)".

## Also suggested (match-base session 2026-11-02 (gildegold), worker 36)
- **FPU compare spelling incl. operand load order:** `and eax,0x4100 / jne` vs `test ah,5 / jp`, `test ah,0x41 / jnp` vs `and eax,0x100 / je`; which side loads first decides `fld`/`fcompp` vs `fcomp mem`. Needed `money * 0.22f < v` (ai_DecideSpy), `!(x >= 1.0f)` (ai_DecideThreaten), `d[3] > x` (ai_EvalMayor). Proposal: for a hunk differing only in the fnstsw test or load order, name the C spelling giving the original's form ("left operand loaded first, branch on C0|C3 = `a <= b` false -> write `b < a`"). Repro: `uv run dcp asmdiff ai_DecideSpy` at gildegold 2bd5ef5^. Cost: ~8 build/grade cycles.
- **Repeated test eliminated on our side:** ai_DecideMayor's original re-tests `test cl,0x45` in both count branches of a loop; VC6 drops them on ours whatever the spelling (build `compiled=0` when only spelling changed). Hint wanted: "the original repeats a test of the same register and mask that ours eliminates", pointing at source structure. Cost: 3 builds.
