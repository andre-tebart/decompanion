---
name: dcp-match-base
description: Run one match-base session of a decompanion project - take functions from the base queue (dcp next) one at a time and raise each to shape + readable by reading the original and fixing the C's meaning, or hand it to the deep queue with a reason (dcp escalate). A session is 8 functions raised or escalated. Use when the user says "match-base", "/match-base", "dcp-match-base", "base pass" or "raise the base grades".
---

# Match-base session: 8 functions, the main checkout

Goal: every item of `dcp next` to **shape + readable**: the code's instruction diff against the original
has only register / stack-slot / scheduling differences left (or it is byte-identical), and a reader can follow
the C without the disassembly. You get there by reading the original and fixing what the C *means*. Byte
identity is welcome when it comes, but allocation, scheduling and generated variant rounds are deep work (the
deep queue, `dcp next --deep`), not this session's.

Hard rules
- Every tool is `dcp ...` from the project root (`--target NAME` for a target other than the first).
  Every `dcp` of the project runs in the project's daemon, which the first command starts (and a new dcp
  build restarts: `dcp: the daemon restarts ...` once, then the command runs). `dcp serve --status` shows it,
  `dcp serve --stop` stops it (before deleting build/). A worktree has a daemon of its own.
  `dcp <command> -h` explains each one; output is one record per line, `key=value`, addresses `0x%08x`.
- Files stay UTF-8 without BOM with LF line endings; any editing tool will do. Never edit `build/` (derived
  state, the store) or `ledger/grades.tsv` (only `dcp session wrap` / `dcp promote` / `dcp debt add` write it).
  Shell heredocs, `sed` and quoted script strings eat backslashes: change string literals (`"\n"`, `"\xNN"`)
  and `#define` continuations with an editing tool, then check the bytes with `dcp dump` / `dcp asmdiff`.
- The sources are the state: the address comment directly above every function's definition
  (`/* 0x10001234, what it does */`), the declarations in `decl/*.dcl`, renames in `names.log` (written by
  `dcp rename`), the unit's current state in its lead comment (the first comment of `src/<unit>.c`: what the
  unit is, then its open questions as `Open:` lines). The lead comment is a brief snapshot, rewritten, never
  appended to: no dates, no history (git is the history). Nothing else; no notes files, no session log.
- A unit is one file, `src/<unit>.c`, in the original's TU order: its head region (includes, types, prototypes,
  the dcp declaration block: everything above the first function), then the functions with the data between
  them. `dcp fn NAME|0xADDR` prints one function with its file and lines (`at=src/<unit>.c:FIRST-LAST`);
  edit it in place.
- Explicit or computed: a name, a type or a struct layout needs evidence (a string, a caller, the use); a
  reasoned guess says so in the comment.
- No grade may fall: `dcp check` fails on M1 (a function whose grade is below the baseline). `dcp build`
  exits 0 before every commit.
- Never write an address of the original into code (`(void (*)(void))0x5de470`, `*(int *)(0x6f9f60 + i)`): the
  relinked program does not hold the original's objects there. Reference the symbol by name (check A1 fails
  the gate on a literal cast to a pointer); a field of a bigger object is a struct member or an offset from
  that object's symbol.

## 1. Start

1. `dcp session start --kind match-base`. It is the gate (no open toolchain or libs obligation, a clean
   working tree, every unit compiles, no error finding, the link ok). On `gate: FAIL` fix what it lists (or
   revert), commit, start again; an `obligation=toolchain.*` / `obligation=libs.archives` line is a human
   decision: stop and hand it to the user. A match-base session is counted in functions (section 4), not
   minutes.
2. `dcp next` - the base queue, first item first. Read the lead comment of its unit's `src/<unit>.c` (its
   `Open:` lines).

## 2. Work loop: one function at a time, always the first item

`dcp next` -> read the function against the original -> fix the meaning -> `dcp build` ->
`dcp grade NAME` -> commit -> next. Never skip an item: one you cannot raise is escalated (section 3).

The item line: `next=0xADDR name=... unit=... section=draft|read experiment=... readability=... gates=B3,Q2,...
dist='N ins / M bytes, size ours vs original'`. `section=draft`: the experiment is below shape; `section=read`: the
experiment is shape or byte, only readability is missing. `gates=` names the failing rules.

### 2.1 Reading: the tools
- `dcp grade NAME` - the failing rules with their evidence (B1..B3: the experiment, byte / shape / draft, or open when
  its unit does not compile; Q1..Q6, Q8: readability, kept apart), `dist`, and the calls without a prototype
  (`M7 consistency:`, the experiment's side).
- `dcp asmdiff NAME` - our instructions against the original's, aligned; `--regs eax=ecx,esi=edi` renames
  registers on our side, `--regs auto` by the renaming most of the function agrees on (the head shows it:
  `regs=...`). Views: `--changed` (only the differing lines, `--context N` around each), `--at 0xADDR` (a
  window, `--context N` each way), `--side ours|original` (one side alone, in its own order); `returns=2/5` in
  the head when the sides return from different numbers of places (merged or duplicated tails).
  The reference check runs in every view: an equal line whose relocated field refers to another object, or to
  other literal bytes, than the original's is `!` with both targets (`(M8: g_a 0x770ae0 | 0x770ae4)`), counted in
  `differing=` and in the head's `refs_differ=`; `ref:` / `literal:` lines name each difference, `refs_open=` the
  references whose symbol has no address yet (no address comment or declaration: not checked).
  `--symbols` prints the call targets, data and string literals by name instead of `X`; `!` marks an equal
  instruction that names another symbol or literal than the original's (a wrong callee, datum or string); `=`
  one that names the same address or literal by another name (an alias, `sym+off` for a bare address: no
  error; two names of ours at one address are a `C.name.alias` error of `dcp check`). A compare against
  an address (`cmp ecx, 0xfb91e4 (or d2_Views+0x81c4)`) also names the array below it the function uses: a
  loop's end pointer lies past the array's end, inside the next object. A `!` line ends with both addresses
  (`0x770ae4 | 0x770ae0`); a floating constant shows its value on both sides; `calls: _ftol ours x2, the
  original x1` lists each callee the two sides call a different number of times, with both counts, whatever the
  alignment (a wrong callee in a hunk of other differences, call sites merged or duplicated on one side); a tail
  `jmp` to a function counts as a call. diffclass prints the same line, and the witness reads the same call set.
  Frames of other sizes are aligned as diffclass aligns them (`frame=0x3bc/0x3b8`): a line that differs only
  by the shift is equal (`~`), so only the real differences show; `--plain` diffs the texts as they are.
- `dcp diffclass NAME` - the hunks and their classes: `fill`, `order`, `regs`, `slots`, `sib`, `fpu`,
  `frame`, `tail` (all explained: shape) and `code` (the rest: a meaning difference until shown otherwise).
  `regs` / `slots` / `order`: the same code under a renaming of registers and stack offsets (a register reused
  once its value is dead may map anew; another order with a renaming is `order`, the renaming in its note).
  `tail`: one side jumps (or branches) to a block the other side has inline, the same code (VC6 merges
  identical return tails and call sequences, or keeps a copy per path); `dcp escalate` counts its instructions
  as explained. `frame`:
  the two frames differ in size (`frame: ours 0xcc, the original's 0xc8`) and these lines differ only by the
  shifted stack offsets; the `code` hunks left beside them are the real cause (often a variable in a register
  on one side, in a slot on the other). A switch's jump and index tables are data, not code: `tables=equal`
  (or `differ` with the entries that point elsewhere: a case body or the case order differs). A jump target is
  a place between instructions, mapped through the alignment: `branch targets differ` lists the jumps the
  alignment pairs whose targets are not the same place, with both target instructions and where the alignment
  puts ours' (a statement structure difference, not shape); `jumps into code hunks: N jumps into the code hunk at
  +X` are target differences that hunk accounts for: read the hunk, not the jumps. grade, asmdiff
  and diffclass read the same extent, so `hunks=0` with equal tables is shape.
  `proof:` (the last line) is the dataflow prover's reading of the whole function: `equal` means it showed both do
  the same (the same stores and calls with the same arguments in the same order, the same branches and return
  value, whatever registers, slots, instruction choice or block layout); `unknown:` names what stopped it and
  where (an FPU instruction, a call or store that differs, an escaped frame laid out otherwise, ...): the first
  place to read. For differing effects it prints both, ours first: `a store differs (address or value): ours
  store4 [ecx0 + 0x10] = arg[esp0+0x8]; the original ...` (`ecx0`: ecx at the entry, `arg[esp0+0x8]`: the argument
  there, `eax@call1@3`: eax after a call, `frame+0x4`: a slot of a local whose address escaped, by its offset). It is
  a report: the grade does not read it yet.
- `dcp disasm 0xADDR` - the original code (`--ours NAME`: ours from its object; `--no-bytes`, `--range +0x200..+0x400`);
  `dcp dump 0xADDR [LEN]` - its constants and strings.
- `dcp refs NAME|0xADDR` - every use and declaration: the callers say what a parameter means.
- `dcp draft 0xADDR --show` - the analyzer's pseudocode, unchanged: a second reading, not the truth.
- `dcp why 0xADDR|NAME` - everything the ledger knows about an address or a function / data name, by question (section,
  owner, start, unit, ref, toolchain): the answer first, the claims stacked under it; then φ there (the objects of H
  at the address: `dcp phi NAME|0xADDR` for one, `dcp phi --many` for the addresses with several), the findings.
- `dcp lint` - clang over the units: cross-unit conflicts (M5), calls without a prototype (M7: the consistency
  convention, a contradiction; `dcp grade NAME` lists them on the function's experiment).
  An M5 line is one symbol: its definition (file:line, unit, spelling) and every declaration that disagrees
  or agrees with it; fix every disagreeing one to the definition's spelling (or the definition, when the
  declarations are right). `does not compile in the all-declarations unit` is a header whose declarations
  are not compared at all until it compiles (a missing include, a macro of another header in its way).
  `dcp grade` and `dcp next` lint the changed units themselves, so their M7 calls are current.
- `dcp headers conflicts UNIT HEADER..` - before including a header into a unit's head: what it collides with
  (supersedes / duplicate / clash / header / call with the original's pushes / vc6, what only VC6 rejects /
  prototyped, per call `safe` or re-grade) and the functions to re-grade; a call / other finding on a line marked
  `@original` / `@vc6` shows `exempt=<marker>` and blocks nothing (a redeclaration with another type never: VC6
  rejects it whatever the marker), an error the unit already had is no finding; `--write` makes the include when only
  duplicates are in the way, in the head region (after its last include, above the first function's address comment,
  never right below a comment); a header the unit already includes is not included again (`already_included=`);
  a text that would detach an address comment is refused (`--at LINE` places the include when the default line fails
  the trial). `warning=declaration-set`: re-grade every function of the unit after the include,
  byte ones first (VC6 /O2 moves code by the declaration set alone): `--trial` compiles the unit with the include
  (nothing written), grades each function as G.grade does (the prover and the reference check too) and lists the
  ones it changes with the grade now, the baseline's and the trial's (`fn=ADDR ... now=byte baseline=byte
  trial=shape m1=yes`); `m1=yes` is a fall `dcp check` would report (below the baseline), and only those count
  (`m1=N`, exit 1); below the current grade but not the baseline is no fall. A dropped duplicate's
  comment never describes its function (Q6 reads the function's own documentation only), so no words are lost to Q6.

### 2.2 Code below shape (`section=draft`)
Explain every `code` hunk from the evidence and fix the C's meaning: a wrong condition, operand or constant, a
missing or extra statement, a wrong type (signed / unsigned compare, `char` vs `int` load, a struct field at the
wrong offset), a call with the wrong arguments, a loop of another form. Stop when only `fill` / `order` / `regs`
/ `slots` / `sib` / `fpu` / `frame` / `tail` hunks remain: that is shape (B2). Reconstructing missing statements is always base
work, however long.
- Every reference is checked, whatever the hunks (the listings read both sides' addresses as `X`): each relocated
  field of ours at an instruction that lines up must refer to where φ puts our object (its address comment or
  declaration), a string or floating constant to the same bytes. A byte or shape function is draft when one does
  not, and a draft lists them first:
  `M8 at +0x2a: ours refers to g_a (0x770ae0), the original's field to 0x770ae4 (g_b)` (another object, element or
  field: two loads swapped, a wrong index), `M9 at +0x..: our literal "a\\b" where the original's field refers to
  "ab" at 0x...` (M10 for a constant: a missing prefix, `1e-7` where the original has `1e-7f`, a wrong value). A
  byte match with such a difference is also an M8 / M9 / M10 error of `dcp check`: equal bytes at this layout only.
  `M.contain` (ill-formed, an error even on a byte match; asmdiff's `contain:` line): `&sym + N` outside sym's
  declared size is no address of sym. Usually a constant written as an address (`&cm_SendRing + 0x4973c0` is the
  mask 0xf00500): write the number; else name the object the address belongs to.
  Named references that only cross (two independent stores in the other order) stay shape when the prover shows the
  effects the same. Not checked, listed as `open:` (`dcp grade NAME`, asmdiff, diffclass): a symbol without an
  address (give it its address comment), and `our literal ... where the original refers to the datum NAME`: either
  the original loads that object (write it, not the literal: a buffer the code changes, a `const` of the unit's), or
  NAME's address comment names a literal of the original (VC6's pooled `1.0f`, the `""` in .bss): decide which.
- Shape can also come from a proof: `B2 shape: the same behaviour, proved (N block pairs); the hunks: ...` means
  the prover showed our code doing what the original does (the same calls, stores, branches and returns) although
  `code` hunks remain. Such a function is done for the experiment; only readability may be left. `dcp diffclass
  NAME` prints the prover's `proof:` line on any function (where it stops, when it does not show it); its
  `verdict=` is the code grade `dcp build` gives (`shape (proved)` for a proof, `draft` with a `ref:` / `literal:`
  line for a reference or a string or constant the original does not have).
- Note `dist` before an edit; after `dcp build`, `dcp grade NAME`: when the distance grew and the
  edit corrected no meaning, revert it (Edit back, or `git checkout -- <file>`). A meaning fix that costs
  distance is kept: say why in the commit message.
- The original walks pointers, not indices; a `cmp reg, <address>` loop end is an array of structs walked to
  its end (write the array, not address arithmetic). Five fields of one record are one struct, not five
  symbols: separate symbols cost a relocated base each.
- A `static const` (or any `const`) global is not a literal to VC6: it loads the value from memory
  (`mov eax, [sym]`) where the original has an immediate. A constant the original codes inline is a `#define`
  or an enum.
- A callee defined above its caller changes the caller's code (registers it leaves alone); the unit's file
  holds the original TU order: never move a function within or between units to make a diff go away.

### 2.3 Readability (`gates=Q...`)
- Q1 / Q2 placeholder names (`ai_Unk4a13e0`, `param_1`, `iVar2`, `DAT_...`): name what you understood.
  Functions and data: `dcp rename OLD NEW --why "the evidence"` (project-wide, whole words, names.log;
  `dcp refs` first; OLD may be `0xADDR` / `exe:0xADDR` for the ledger's name). Several names at once:
  `dcp rename OLD1 NEW1 OLD2 NEW2 ... --why "..."` or `--from FILE` (one `OLD NEW [why]` per line): one
  rebuild for all of them, and nothing is written unless every pair passes; collect the names of a function
  and rename them in one call. names.log keeps the why as dcp received it; Git Bash passes `\\` in an argument
  as `\` (and `\"` inside double quotes as `"`): a why with backslashes (`Menu\CHOOSEPLAYER`) goes in single
  quotes with single backslashes, or in a `--from FILE` line. Rename first, then edit: the rename writes the new name everywhere and logs it (a name already written by hand in some places is
  completed by the rename, not refused). It prints every changed file with its replacements; a refusal is an
  `error=` record with exit 1 and nothing written: read it, never assume the rename happened. A view
  (`ai_Unk7603a0B`) keeps its name when its datum is renamed (the note lists it): rename it on its own.
  Locals and parameters: edit the function.
- Q3 address literals and Q4 raw access (`*(T *)(p + 0x1c)`, macros built on such casts): a typed field, a
  struct, the symbol (see the hard rule on addresses). A datum the unit reads as another type is a view macro
  with the address comment on its line: `#define NAME (*(T *)&datum)  /* 0xADDR */`, or
  `(*(T *)((char *)&datum + OFF))` for a part of it (`(*(T *)(array + N))` too when `array` is declared as an
  array in the macro's file: its name is its address, N counts elements). `(*(T *)datum)` / `(*(T *)(ptr + N))`
  (no `&`, no array: through the datum's value) is raw access and keeps the function at draft.
- Q5 markers (ROUGH, TODO, `@rough`): remove them once the function is written.
- Q6: the address comment says what the function does (`/* 0x4a3000, sends the login reply */`). Only the
  function's own documentation counts: the address comment above its definition, or its declaration's comment in
  its owner header `include/<unit>.h`. A copy's comment in another unit's head or header does not, nor a text that
  only names a file (`/* 0x4025c0, ch.h */`, `as in dd_vesa.h`, `defined elsewhere`).
- M7, consistency: every call has a prototype (`dcp lint` evaluates it; the original was consistent C, so a
  call without one is a contradiction, not a style point): the callee's prototype lives in its defining unit's
  header `include/<unit>.h`; include that header, never write a second prototype (`dcp refs NAME` shows them).
  When that include does not compile because the unit's head redeclares the header's symbols (its own
  prototype, a partial struct view of a type the header defines, a named object declared `extern GAPDATA`:
  C2371 redefinition, C2198 too few parameters and the like), fix the head (`dcp headers conflicts UNIT HEADER`
  lists what is in the way): include the header, delete the local declarations it supersedes, correct the
  calls and accesses that only compiled against them. Commit
  that on its own, before the function: `<unit>: head includes <x>.h (typing)`; it does not count toward the 8,
  and `dcp check` must show no M1 (a debt item, 2.6, is held at its declared grade and listed as `M1.debt`). A byte-matched
  function is evidence of what the original declared: when a correction changes its bytes, the correction is
  wrong, not the match, unless the match is no evidence at all (2.6). Find which side is: fix the
  header when its signature or type is the guess, or keep the original's spelling with `@original why` (the
  matched caller as evidence) when the original really called it that way. That spelling stays in the unit
  that needs it, never in a shared header (two headers that disagree can never be included together: M5): a
  cast macro in the unit's head next to the include (`#define d2_MoveObjS ((void (*)(short, short, int))d2_MoveObj)
  /* @original main passes shorts */`), used at those calls. A fall is no way around a conflict (2.6 says when
  one is right), and neither is a copied prototype or a local struct view. A conflict you cannot settle in the
  session: leave it, add `Open: head: include/<x>.h, <symbol> unsettled (<why>)` to the
  unit's lead comment, and leave M7 open for the calls it blocks.
- `extern GAPDATA name[]` (`__declspec(align(1)) unsigned char`) is for the unnamed gap blocks only
  (`full_data_<addr>`; it keeps the full rebuild's data packed). An object you name gets its real type and one
  declaration, in its unit's header (section 2.5, gap data).
- `@original why` / `@vc6 why` on a declaration line only with evidence (a byte-matched caller that needs it).

### 2.4 Commit
One function, one commit: `<unit>: <name> shape + readable (match-base)` (`byte + readable` when it got there).
`dcp build` exits 0 first. A message of more than one line goes through a file: write it to a scratch file and
`git commit -F <file>` (on Windows a here-string piped into `git commit -F -` can arrive as a pathspec). Check that
the commit went in (`git status` clean) before the next function.

### 2.5 Other units, headers, data
- Another unit may change when the meaning needs it and the change is right for it too; a header edit
  recompiles only its includers, and no function anywhere may get worse (`dcp check`: no M1) except by
  an accepted fall (2.6).
- Never rename struct fields or types other units' matched code uses without checking them (`dcp refs`).
- Data errors (D1, D4, D5, D7, D8, D9) are not base work, except the ones your own change causes; `dcp data map UNIT`
  shows a unit's data when a function needs it, with `room_ref` lines for the addresses after a datum the original's
  code reads. D9 (the original reads the padding our object gives a datum), D7 (a view past its container's
  declared size) and D8 (the original's code uses more bytes as one object than the declaration holds: a field
  access, a loop bound, a block copy, a reader call) are run-time corruption the gate cannot see otherwise: declare
  the object at the size D8 names, with the names inside it as views or fields of its type. A reader or copier of
  the game (`vfs_fread(buf, size, n, f)`) tells S.extent its size through
  `dcp decl add "0xADDR writes ptr=a0 size=a1*a2 -- why"`.
- Gap data: the `full_data_<addr>` / `full_rdata_<addr>` blocks (defined in the gap block at the end of `src/main.c`,
  `extern GAPDATA` elsewhere) are bytes no symbol covers yet: name, type, extent and owner are all unknown, and
  their place in main says nothing about ownership. When the function you raise shows what one is, settle all
  four, in one commit of its own before the function: `<unit>: data <name> from the gap block (typing)`; it
  does not count toward the 8.
  - Name and type it from its users and its bytes (`dcp dump`, `dcp refs`; `{0,0,0,0,0,0,0xe0,0x3f}` is the
    double 0.5). The size is the object's, not the gap's: a gap runs to the next known address and may hold
    several objects; split it, the rest stays a `full_` block at its own address.
  - The owner is the unit whose data block the address lies in (VC6 lays out one object's data contiguously, in
    link order): between two of that unit's definitions in `dcp data map UNIT`, or reached only from that unit's
    functions (`dcp layout literals`, `dcp refs`). Move the definition into that unit's file among its data in
    address order (`dcp data map UNIT` shows where), with its address comment, and its one declaration into `include/<unit>.h`; drop every
    `extern GAPDATA` of it and use the typed name at each site.
  - `dcp check`: no D1 (overlap), no D4 (address order), no D8 (smaller than the original's object), no M1
    (no function got worse); a matched user
    still matching confirms the address (`M.data.site`). A move that breaks one of these was the wrong owner or
    the wrong size: undo it, do not answer it with alignment or padding tricks.
  - An address between two units' blocks with users in both is a boundary question for layout: name and type
    it in place if you must, leave it in the gap block, and add `Open: data: <addr> <name>, owner <A> or
    <B> (<evidence>)` to the unit's lead comment.

### 2.6 Accepted falls (your judgement)
The goal is a code base that is, as a whole, closer to the original's source, not the largest count of
matches. A change can cost a function its byte or shape grade (M1 reports the fall). Accepting it is your
call, made on this criterion: the fall is acceptable when the change brings the code base as a whole closer to
the original (truer types, fewer views, casts and duplicated records, headers the units can include) **and**
the match it costs is no evidence of the original's source. The typical case is a VC6 declaration-set
tie-break: the match flips on declaration changes unrelated to the function (an empty include, an extra
typedef, a prototype nothing calls), so it never said anything about what the original wrote. A fall from a
wrong change is not acceptable (a signature, a type or a spelling the original's bytes contradict): fix the
change, or keep the original's spelling (2.3). When you are not sure which it is, find out (`dcp asmdiff`,
`dcp diffclass`, try the change without its unrelated parts) before deciding.
Each accepted fall is debt: `dcp debt add NAME --to shape|draft --why "<the change, why it is closer, why the
match was no evidence>" --waits-for "<what has to settle first: a prototype, a header, a unit's layout>"` (main
checkout; `--readability draft` when readability fell too): it lowers that one function's entry in
`ledger/grades.tsv` and records the grade before, the last witness commit, the reason and what it waits for;
`dcp check` then holds the function at the declared grade and lists it (`M1.debt`), and fails past `[gate]
max_debt` items when it sets one. `dcp debt list` shows them all: walk them once the structure settles (many share one
cause). Commit `ledger/grades.tsv` with the change. `dcp promote` (and the wrap) raise entries only and refuse a
fall no debt item covers.

## 3. Escalation to the deep queue
When only allocation or scheduling is left (`regs`, `slots`, `order` hunks the classes do not explain away, or
the code is shape and only byte identity is missing), or a generated variant round would be needed:
`dcp escalate NAME "why"`, build, commit `<unit>: <name> -> deep (match-base)`. The reason lists what was
read and tried and the exact remaining hunk (`asmdiff` lines). `dcp escalate` refuses a reason that only names
missing statements, and one that admits a part not read against the original yet (not reconciled / checked /
compared / verified, hard to judge): reconstruction and reading the whole function are base work. It also
refuses while our instruction count differs from the original's by more than max(12, 1/100 of the original's)
(the `asmdiff` head: `ours=` / `original=`): allocation, slots and frames move a few instructions (no shape
function on gildegold differs by more than 7), a larger difference is missing or wrong statements. When
allocation really causes it (extra saved registers, spills you have read in the asmdiff), say how:
`--size-explained "why"` (kept in the reason); a function whose behaviour the prover shows the same (`proof:
equal` in `dcp diffclass NAME`) is not held to the size. It refuses too on a concrete difference: a call or a
store to a global that one side has and the other never refers to (`differs:` in `dcp diffclass NAME`, e.g.
`the original +0x67 calls 0x5de518 (_ftol); ours never refers to it`), or a reference of ours the original's field
does not make (`ref:` / `literal:` in `dcp diffclass NAME`). That is a meaning difference (a missing call or
assignment, a wrong type converted, a wrong object, index or literal); fix it. Only when you have read that it is none (the call reached
another way), say why: `--divergence-explained "why"` (kept in the reason). A function you raise to shape + readable that still carries a
stale `@deep` / `@stuck` tag: `dcp escalate NAME --clear`, build again.

## 4. When to stop
A session is **8 functions** raised to shape + readable (or byte + readable) or escalated, then the wrap-up.
Never stop early: a hard function is escalated, not a reason to end; a long queue is not a reason to end;
"it feels long" is no clock. One raise or one escalation is one commit: count the commits and stop at 8
(escalations count). A reconstruction of a big function (~1000 instructions, missing statements) may take most
of a session; that is expected base work, not a reason to escalate it.

## 5. Wrap up
1. Keep the function in progress if it builds and nothing got worse (but by an accepted fall, 2.6), else
   revert; `dcp build` exits 0.
2. `dcp session wrap`: builds, links, checks every target, promotes the grade baseline and prints the
   computed report (errors, byte and readable counts before -> after, `grades changed` per function, renames,
   the next item). It must say `gate: ok`. It promotes nothing while src/, include/ or decl/ hold uncommitted
   changes (`promote=refused  dirty=N`: a grade needs its commit): commit the last function first.
3. Rewrite the lead comment of every unit you touched to its current state (a few lines): what the unit is,
   then one `Open:` line per unit-level question still open (head conflicts, data owners). Drop what is
   settled; never add a dated or "this session" line. Escalated functions carry their reason in their tag,
   what a function does goes into its address comment, types and names into the code.
4. Commit: `git add -A && git commit -m "session: match-base wrap (<units>)"` (the baseline).
5. Final message: the report's first lines (byte / readable before -> after), each function raised or
   escalated with its new grade, the renames, the next `dcp next` item. Stop.
