# Shape detection vs. gildegold's @deep functions — findings and tooling plan

## Context

gildegold has 416 functions in the deep queue (`dcp next --deep`): 360 `code=draft`, 41 shape, 15 byte (Q-only).
Question: are the escalated drafts really not behaviourally identical, and can shape detection see more?

### Findings (`dcp diffclass` over all 360 drafts + ~25 `asmdiff` samples)
- 247/360 have branch-target diffs, 68 needed the frame-aligned diff, 324 have >50% of differing weight in `code`
  hunks. The classifier (`diffclass.rs` + `x86.rs:explain`) is textual and per hunk (hunks joined within 4 equal
  instructions): one non-renamable line poisons the whole hunk.
- **Behaviour-identical but graded draft** (most samples):
  - instruction selection: add/mov vs lea (d3io_AttachStock, ai_BuildingName), lea fold/split
    (ai_HasThreeStockedBuildings), `mov cl,[esi]; test cl,cl` vs `cmp byte ptr [eax],0` (bio_rd_s), copy
    propagation (qnt_Build)
  - dead computations / constant held in a register (sv_RemoveGroupMember, hmt_RandomTextOffset)
  - function-wide register swaps crossing callee-saved push/pop (vfs_EntryPath ebx↔ebp: 50 `regs` + one 56-line
    `code` hunk at the epilogue; evt_FindLogic, ai_ChooseMission, hmt_ClearOffices, hmt_Init, d2_GetPixelColour)
  - block layout + branch inversion (ahm_SendSetShare, ahm_SendSetPlaceValue, ahm_AddValue)
  - duplicated / merged return tails (ai_TokenMayor, amt_GetOffice; rd_BuildRoad per field report)
- **Real meaning differences that escalation let through** (base work):
  ai_SaveNetworkGame (original has an extra `mov byte ptr [X], dl` store), ch_AnimDone (ours `mov al`, the
  original zero-extends into eax: return type width).
- **Shape side**: relocated operands are masked `X`, so shape never checks callee/datum identity; `asmdiff
  --symbols` `!` is mostly alias noise (`_real@3f800000` vs `ai_Unk5eb780`, `_imp__socket` vs `0x5eb29c`) —
  bug-reports/asmdiff-alias-flagged-as-mismatch.md. Field reports improvement-reports/asmdiff-regs-auto.md and
  diffclass-tail-epilogue-class.md ask for parts of this.

### Decision (user)
A function the prover proves behaviourally identical is **raised to shape** (new B2 clause); output says which
proof applied. `dcp escalate` (deep) refuses on a concrete meaning divergence.

## Phase 1 — cheap yield inside diffclass (land first, measure)

Status (2026-11-02): done on shape.rs / diffclass.rs / asmcmd.rs. Item 1 as the identity logic of asmdiff
--symbols (no module of its own: our unrelocated numbers, floating constants, switch-table labels, pooled
literals, `calls differ`); item 2 as `asmdiff --regs auto` and the hunk renamings (renewed where a register is
overwritten, with reordering and stack-offset remaps, no limit on the registers); item 3 as saves (a push of a
callee-saved register not yet written, the pops before a ret) that pair whatever register they name, and the
code hunks counted as moved instructions with the explained hunks' lines; item 4 as the tail class (jmp and
conditional jumps) with `returns=` in the asmdiff head. Measured on gildegold af0cd2c: 32 draft -> shape, none
the other way; vfs_EntryPath, hmt_ClearOffices, evt_FindLogic, ai_TokenMayor shape.

Order: items 2–4 are explainers. Build them over the typed instructions (`dis::Ins`, compared structurally: equal
modulo a register bijection, a stack-slot remap, a push/pop set) on `diffclass::FunctionCompare`, not as more
regular expressions over the listing text; Phase 2's lift reads the same record.

1. **`ident.rs`** (new): `enum Ident { Addr(u32), Lit{bytes,float}, Sym(String) }` for each of our relocations:
   aligned-site read of the original's operand (reuse the opcodes pairing idea of `diffclass.rs:aligned`), else
   `rules.rs:name_registry` (make `pub(crate)`) via `coff::undecorate` with `__imp_` stripped, literals by content
   against the image, else opaque `Sym`. Replace the identity logic in `asmcmd.rs:reloc_name` with it: same
   address under two names prints `=` not `!` (fixes the bug report). Add `kind:name` to `G.grade`'s needs.
2. **Function-wide register correspondence** in diffclass: vote a bijection from difflib pairs of register-masked
   texts, rename ours, diff again; hunks then classify against the renamed text. Exposed as `asmdiff --regs auto`.
3. **Callee-saved prologue/epilogue normalisation**: save/restore push/pop sets compared as sets, a move across
   a `pop` before `ret` counts as `order`.
4. **`tail` class**: a hunk where one side jumps to a block instruction-equal (modulo the renaming) to a block the
   other has inline (fixes ai_TokenMayor / amt_GetOffice / rd_BuildRoad). Add `returns ours=N original=M` to the
   asmdiff header (asmdiff-header-return-count.md).
5. Measure: re-run the deep batch; vfs_EntryPath, hmt_ClearOffices, evt_FindLogic, ai_TokenMayor should turn shape.

## Phase 2 — dataflow-equivalence prover (report first, then grade)

Status (2026-11-02, graded): G.grade (version 9) raises a function the shape classes leave draft to shape when the
prover shows it equal (grade.rs `verdict`, computed with the shape verdict on every core and held with it; B2
names the proof). The negative control is `equiv::tests::mutants`: on the corpus (`DCP_EQUIV_DUMP` from diffclass,
`equiv::tests::corpus`), 17464 one-place mutants of the 385 functions proved equal; it found five holes (the
return's esp and callee-saved registers, slots lost at a join leaving an escaping frame, a tail jump's
arguments, the argument cells of a deferred cleanup), and the 24 mutants still shown equal were each read and
cannot be seen (dead stores and registers, a mask of a constant). Grading binds our relocations through aligned
sites only (the ledger's names are not among G.grade's inputs), so diffclass's `proof:` can show a few more.
gildegold af0cd2c: 97 functions draft to shape; byte unchanged, the must-differ functions draft, cold grade ~0.6 s,
warm build 34 ms.

Earlier status: first slice in equiv.rs, reported by `dcp diffclass` (`proof:`), not graded. One module:
the arena (linear normal form, partial registers, loads keyed by the memory state, conditions canonical under
mirror and complement), blocks paired in lockstep with a location correspondence narrowed to a fixpoint (a block
may pair with several), our relocations bound through aligned sites (equiv::bind), calls compared by target and
the slots pushed since the last call (saves of callee-saved registers left out; through memory without `add esp`
after: stdcall), an escaped frame (an address passed on, an indexed access, rep stos / movs) compared as memory
from the escaped address (locals) or by offset (arguments); the x87 stack as locations with its depth (loads and
stores by width, fild / fistp, the arithmetic with its reversed and popping forms, compares through fnstsw / sahf /
test ah with the parity conditions, the stack as a call's arguments and st0 as its float return), 8-byte stack
values, sbb / adc on a compare's carry, the space a `sub esp` reserves outside the prologue as a call's arguments
once written; values known on every path (constants, stack addresses, entry values) carried across blocks;
conditions in one 32-bit form; loads past stores they do not overlap; bytes and words anywhere in a stack cell;
relocations no aligned site binds bound through the ledger's names. Not yet: switch tables, flags across
blocks, string scans (repne scasb), return liveness (eax always compared), an escaped object apart from the frame
around it (most remaining concrete differences are an escaped frame laid out otherwise: escaping objects alone
was tried and dropped, where an object ends is in neither binary and the guesses differed between the sides),
loads kept in a register against reloaded across blocks. gildegold af0cd2c: equal for 266 of 317 byte functions
sampled (none reports a difference), 95 of 259 shape, 77 of 1557 draft; ai_SaveNetworkGame and ch_AnimDone come out not equal (an extra store, eax at the return).

New flat modules in native/dcp_core/src:
- **`equiv_lift.rs`**: `dis::Ins` → micro-ops. dis.rs (iced-x86) already gives the mnemonic id, typed operands
  (registers as `iced_x86::Register`, memory with segment / base / index / scale / disp / size), the disp / imm /
  branch field offsets (`Ins::field_at`: the link to a relocation), flow, targets and def-use register sets;
  `dis::decode` reads our object's bytes as well as the image's. 8 GPRs with partial writes; flags as `Flags(op,a,b,w)`; x87 stack of node ids (fxch permutes, `fnstsw ax`
  inserts FSW into eax); `rep movs`/`repne scas` opaque.
- **`equiv_expr.rs`**: hash-consed arena; lea→Add/Mul, commutative sort, constant fold, `xor r,r`=0,
  Lo8(Insert8) simplification, Zx/Sx; conditions as outcome masks over the compare (so `test ah,0x41` ≡
  `and eax,0x4100`, swap mirrors, negation complements); `Load(addr,w,epoch,may-alias stores)`.
- **`equiv.rs`**: CFG per side, liveness over locations (regs, flags, non-escaped stack slots, FPU slots);
  stack as `SP0+c`, non-escaped slots are locations, locals renamed by correspondence; callee-saved pushes/pops as
  save slots checked per side at `ret`; bisimulation over path pairs between cut points with a correspondence
  refined to a fixpoint; branch pairing direct or swapped on complemented condition; jmp threading; many-to-one
  pairing (tail dup/merge); calls = pushed slots since last call, cleanup from mangling / `add esp` must agree,
  eax/ecx/edx fresh after. Return liveness from our definition's return type (void / int / int64 / float; parse
  failure → eax live, divergence not concrete).
- Output `Outcome { Equal(Proof{pairs, notes, assumed}), Diverge(Div{kind, at, ours, theirs, concrete}),
  Unknown(why) }`. Unknown never raises, never blocks.
- Deterministic budgets (≤100k nodes, `4·(nA+nB)+64` pair visits); target 0.2–2 ms per draft function.

Integration:
- **grade.rs**: identities + return kind added to the memo `Key` (HELD); `compute()` calls `equiv::prove` only
  when `!v.shape`. Equal → `code="shape"`, failing text `B2 shape: proved dataflow-equivalent (N block pairs;
  branch inverted k, tail merged m): <summary>`, fact gets a new top-level `proof` key (`hunks` stays
  `{class:int}` — matchcmd.rs reads it with `as_i64`). Diverge/Unknown appended to the B3 line. Bump G.grade
  version. `grades.tsv` format unchanged; M1 then guards prover regressions.
- **asmcmd.rs / matchcmd.rs**: `diffclass` and `grade NAME` print `proof: equal|divergence|unknown` with evidence
  and paired addresses; verdict `shape (proved)`.
- Land reporting-only in diffclass first, enable the B2 raise once the negative control passes.

## Phase 3 — escalate gate (`queues.rs:level_command`)

Status (2026-11-02, done): the prover's stops are not differences (it stops on 101 of the 156 shape functions it
does not prove with "a store differs", "a call differs" ...: order, slots it does not follow), so the gate uses a
separate, narrow witness (equiv::witness): a call (direct, through an absolute address, a jump out) or a store to
an absolute address that one side reaches from its entry and the other never refers to (a callee anywhere in its
operands; a store within 0x1000 of an address it names: a field through a register holding the object's
start). The original's side counts only when every one of our relocations is bound. On the corpus (2020
functions of gildegold af0cd2c): no witness on any of the 560 byte and shape functions, 178 of 1460 drafts
(157 a call of the original's, 17 a call of ours, 4 a store of the original's); every sample read was real
(`_ftol` where the original passes the float, `d2_ClickedId = -1` missing). `dcp escalate` refuses it
(`--divergence-explained "why"`, kept in the reason); an equal proof lifts the size refusal; `dcp diffclass`
prints it (`differs:`).

The control found two binding faults (`bind`), fixed: an aligned site pairing two reordered calls bound one
symbol to the other's address (two names at one address: neither site binding is trusted, the ledger's name
wins), and a literal bound where the original holds other bytes (`_real@bf800000` -1.0 at the original's 1.0,
`"d2_fadeinfo"` at `"d2:fadeinfo"`): the prover had shown those functions equal. G.grade version 10.

Consistency (G.grade 11, 12): the held verdict is keyed by the relocations' symbols, literal bytes and ledger
addresses too (a changed string, callee or name leaves the code bytes alone); grading binds through the ledger's
names at one address (names::unique_addrs over the name claims of names::NAME_RULES, now among G.grade's needs)
and dcp diffclass / dcp escalate through the same map, so the proof is one: on the gildegold af0cd2c clone 16
more functions shape, and dcp diffclass's verdict (`shape`, `shape (proved)`, `draft` with a `literal:` line)
equals the grade on all 1816 draft and shape functions.

The same functions were shape by the classes too: the listings compare relocated fields as X, and M9 / M10
(constant_mismatches) run on byte matches only. G.grade 10 checks every shape function's literals at its
aligned sites (equiv::literal_mismatches; a literal the original holds at any address its code names is not
one: reordered pushes pair them crosswise): gildegold af0cd2c, 6 shape functions to draft, each real
(d3fl_FarDist -1.0 / 1.0, d2_StartFade and ai_FavourComment strings, ai_FilePickWindow "s_menu_fileselector",
d3_MatInverse a double 1e-7 against the float's, unk_Unk4f2660 0.00625 / 0.0125).

After the size check: a concrete `Diverge` refuses deep escalation and prints the evidence; `--divergence-explained
"why"` as safety valve (recorded in the reason). An Equal proof skips `size_unexplained`. Enabled only after the
negative control shows zero concrete divergences. Update docs/match.md (B2, ladder) and
skills/dcp-match-base/SKILL.md §3.

## Phase 4 — completeness
Effect lag across branches, switch tables (pair successors per index via `compare_tables`/`read_entry`), wider
x87 coverage, escaped-local regions.

## Soundness (stay conservative)
Unproven disjointness = may-alias; `lea` of a slot escapes it; calls clobber non-local memory. Flags are a
location; CF/OF use after non-cmp/sub/test → Unknown. x87: empty at calls, no reassociation, depth mismatch or
control-word change → Unknown. `and esp`/alloca/non-constant esp → Unknown. Unresolved `Sym`s bind only through
aligned sites, are listed under `assumed`, never make a divergence concrete.

## Verification
- Rust unit tests in equiv.rs with a test-only Intel-text parser so the sampled gildegold listings paste in (like
  diffclass.rs tests): an equal case + a mutant per category (lea/add, `cmp byte [eax],0`, copy propagation, dead
  lea, ebx↔ebp across pop, swapped clamp blocks, tail dup, FPU test forms). Must-diverge: extra store
  (ai_SaveNetworkGame), `mov al` vs zero-extend under int return (ch_AnimDone), swapped call args, store width.
  Traps that must never be Equal: aliasing store between load and reuse, `inc` between cmp/jcc, fsub vs fsubr,
  stdcall/cdecl cleanup mismatch. One or two byte-level tests via `dis::decode` +
  `coff::testlib::code_obj` for relocation identity. No new e2e test; `cargo test` stays fast.
- gildegold: batch `dcp diffclass` over `dcp next --deep -n 500` before/after each phase and tally verdicts;
  negative control = prover over every byte and shape function, any Divergence is a prover bug (gate for phase 3);
  ai_SaveNetworkGame and ch_AnimDone must come out concrete divergences.
- Performance: `dcp-bench` (tools/bench.rs) — warm `dcp build` stays <1 s, read commands <10 ms; G.grade cold cost measured
  (today ~0.17 s).
