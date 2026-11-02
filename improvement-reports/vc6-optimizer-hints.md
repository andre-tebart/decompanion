# Knowledge note or `dcp hint` for known VC6 optimizer behaviours

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** skill docs / new command
- **Problem:** `snd_UpdateRain` needed `(float)(x * 88.9f) / d` to stop VC6 folding `x * 88.9f * (1/d)` into one constant. Finding the spelling took several build–asmdiff rounds.
- **Proposal:** a short note in the skill, or a `dcp hint` command, listing known VC6 behaviours and the spellings that steer them:
  - constant folding
  - sharing one reciprocal across divisions by the same value
  - merging identical call tails (see diffclass-tail-epilogue-class.md)
  - threading jumps past known branches
  - per-scope stack-slot packing
- **Cost of not having it:** about 30 minutes across the float-heavy functions.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 5)
Patterns behind most of this worker's `code` hunks (a `dcp hint NAME` that spots them would help):
- original reads a global as a byte (`mov al,[x]; test al,N`) where the project declares an int or a union (ai_GameFlags, snd_AmbientOn);
- inline `memset` / `strcpy` that the draft wrote as stores or a loop (five `-1` stores through one pointer; `"Beamed home"` copied as three dword moves);
- `fmul qword` whose constant equals `(double)0.1f`, i.e. the source used the `f` suffix;
- if/else blocks in the opposite order (`je` to the other block), or a shared failure exit;
- the order of struct-field stores changing the base register.
- Cost: large; several rounds per pattern. Related: diffclass-idiom-hints.md

## Also suggested (match-base session 2026-11-01 (gildegold), worker 7)
Skill notes for 2.2 (next to "const is not a literal"):
- a zero-extended 16-bit return compared as signed 32-bit (`and eax,0xffff; cmp eax,5; jge`) can be a `min()`/ternary macro mixing int and ushort; it explained the double roll in ai_DecidePartnerOtherSex and gave a byte match;
- a `dec reg; test reg,reg; jne` counter came out as `for (j = 6; j-- != 0;)`;
- a VC6 `rep stosd` with count `6 - n` comes from a plain zeroing loop, not from `memset`.
- Cost: several variant builds.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 8)
- `j--; i = ...; } while (j != 0)` vs `while (--j)`: the original has `dec` before `idiv`, then `test`.
- A zero fill `for (i = n; i < 6; i++) who[i] = 0;` compiles to a bare `rep stosd`; `memset` gives `rep stosd` + `rep stosb`. A diffclass hint "stosd without stosb: a zero loop, not memset" would help.
- In 0x4a9700 / 0x4a9880 a mid-function `push ebx`/`pop ebx` looked like an allocation quirk; it vanished once the zero-fill loop was right (4 builds spent on `__inline` / nested-block hypotheses).

## Also suggested (match-base session 2026-11-01 (gildegold), worker 14)
- `memcmp(o, "tp_TUER", 8)`: ours `repe cmpsd` x2 vs original `repe cmpsb` x8 (sv_HoverPick). A known VC6 variant; worth a diffclass hint.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 22)
- **Caller-saved register carried across a same-unit call:** gv_ListEntry's draft comment said the original "takes it from edx" (reads as not reproducible in C), so the draft read limits from the open flags instead of `r->kind`. In fact VC6 keeps edx (the kind) across the call to gv_SizeOpen because that callee is defined earlier in the same unit; `kind = g->kind` once gave byte identity. Hint wanted when the original reads eax/ecx/edx right after a call to an earlier same-unit function: "edx carried across the call to gv_SizeOpen: the value loaded before the call". Repro: `git show 6746c06~3 -- src/gv.c`, `uv run dcp disasm 0x4ef570` (edx loaded at +0x5, used after each call). Would have been costly if the comment had led to an escalation.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 35)
- Local declaration order/renaming did not move frame slots under /O2 (~6 builds to establish). Skill line: "declaration order does not move frame slots; use slot hunks for deep" (note: earlier sessions found initialisation order and block scoping can matter; see frame-slot-layout.md).
- Writing the partner-flags assignment separately in each branch keeps VC6 from folding it into a branch-free `sbb` form the original lacks.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62) - pointer-temp form for `ai_Goods`
- Writing the goods-kind lookup as `char *good = ai_Goods + id * 0x41; *good` gave byte identity in gm_GoodsDemand (0x4ff8c0); the same `add; mov [reg]` hunk was earlier recorded as "tried ... unchanged" in gm_LoadTables and remains in gm_UpdatePrices. Want a lint/hint suggesting the pointer-temp form for `ai_Goods[x * 0x41]` with this hunk.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66) - switch range
- VC6 drops case labels that share the default's body, so the switch range (`cmp eax, N`) shrinks. When `cmp eax, N` differs on a switch, a hint like "the original's range is larger: case labels without their own body may have been dropped" would help. ~3 tries on gm_SexForTitle (0x503f50).

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- VC6 emits `fild` + `faddp` instead of `fiadd` when the int is a call result used inline; fix was calling `util_RandomU(...)` inside the expression, not via a variable. Proposal: a diffclass fpu note when a hunk differs only fiadd vs fild+faddp. ~5 minutes.
