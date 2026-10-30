---
name: dcp-match-base
description: Run one match-base session of a decompanion project - take functions from the base queue (dcp next) one at a time and raise each to shape + readable by reading the original and fixing the C's meaning, or hand it to the deep queue with a reason (dcp escalate). A session is 8 functions raised or escalated. Use when the user says "match-base", "/match-base", "dcp-match-base", "base pass" or "raise the base grades".
---

# Match-base session: 8 functions, the main checkout

Goal: every item of `uv run dcp next` to **shape + readable**: the code's instruction diff against the original
has only register / stack-slot / scheduling differences left (or it is byte-identical), and a reader can follow
the C without the disassembly. You get there by reading the original and fixing what the C *means*. Byte
identity is welcome when it comes, but allocation, scheduling and generated variant rounds are deep work (the
deep queue, `dcp next --deep`), not this session's.

Hard rules
- Every tool is `uv run dcp ...` from the project root (`--target NAME` for a target other than the first).
  First check `uv run dcp serve --status`; when no daemon runs, start one with `uv run dcp serve` (it
  detaches and returns) and leave it running: every `uv run dcp` of the project then runs in it (about 0.2 s a
  call instead of 1 .. 3 s, same output). Without it every command still works, only slower. A worktree needs
  its own (`dcp serve` there).
  If `uv run` fails with "failed to remove file ...dcp.exe" (access denied), an old daemon holds the exe: run
  `uv run --no-sync dcp serve --stop`, then retry.
  `dcp <command> -h` explains each one; output is one record per line, `key=value`, addresses `0x%08x`.
- Files stay UTF-8 without BOM with LF line endings; any editing tool will do. Never edit `build/` (derived
  state, the store) or `ledger/grades.tsv` (only `dcp session wrap` / `dcp promote` / `dcp accept` write it).
  Shell heredocs, `sed` and quoted script strings eat backslashes: change string literals (`"\n"`, `"\xNN"`)
  and `#define` continuations with an editing tool, then check the bytes with `dcp dump` / `dcp asmdiff`.
- The sources are the state: the address comment directly above every function's definition
  (`/* 0x10001234, what it does */`), the declarations in `decl/*.dcl`, renames in `names.log` (written by
  `dcp rename`), notes in `notes/units/<unit>.md`. Nothing else; no session log.
- A unit is one file, `src/<unit>.c`, in the original's TU order: its head region (includes, types, prototypes,
  the dcp declaration block: everything above the first function), then the functions with the data between
  them. `uv run dcp fn NAME|0xADDR` prints one function with its file and lines (`at=src/<unit>.c:FIRST-LAST`);
  edit it in place.
- Explicit or computed: a name, a type or a struct layout needs evidence (a string, a caller, the use); a
  reasoned guess says so in the comment.
- No grade may fall: `dcp check` fails on M1 (a function whose grade is below the baseline). `uv run dcp build`
  exits 0 before every commit.
- Never write an address of the original into code (`(void (*)(void))0x5de470`, `*(int *)(0x6f9f60 + i)`): the
  relinked program does not hold the original's objects there. Reference the symbol by name (check A1 fails
  the gate on a literal cast to a pointer); a field of a bigger object is a struct member or an offset from
  that object's symbol.

## 1. Start

1. `uv run dcp session start`. It is the gate (no open toolchain or libs obligation, a clean working tree, every
   unit compiles, no error conflict, the link ok). On `gate: FAIL` fix what it lists (or revert), commit, start
   again; an `obligation=toolchain.*` / `obligation=libs.archives` line is a human decision: stop and hand it to
   the user. The session clock it mentions bounds layout sessions; a match-base session is counted in functions
   (section 4), not minutes.
2. `uv run dcp next` - the base queue, first item first. Read `notes/units/<unit>.md` of its unit (its **Open work**
   first) when it exists.

## 2. Work loop: one function at a time, always the first item

`uv run dcp next` -> read the function against the original -> fix the meaning -> `uv run dcp build` ->
`uv run dcp grade NAME` -> commit -> next. Never skip an item: one you cannot raise is escalated (section 3).

The item line: `next=0xADDR name=... unit=... section=draft|read code=... readability=... gates=B3,Q2,...
dist='N ins / M bytes, size ours vs original'`. `section=draft`: the code is below shape; `section=read`: the
code is shape or byte, only readability is missing. `gates=` names the failing rules.

### 2.1 Reading: the tools
- `uv run dcp grade NAME` - the failing rules with their evidence (B1..B3 code, Q1..Q7 readability) and `dist`.
- `uv run dcp asmdiff NAME` - our instructions against the original's, aligned; `--regs eax=ecx,esi=edi` renames
  registers on our side. Run it first on every big `code` hunk: a pure register rotation reads as `code`.
- `uv run dcp diffclass NAME` - the hunks and their classes: `fill`, `order`, `regs`, `slots`, `sib`, `fpu`,
  `frame` (all explained: shape) and `code` (the rest: a meaning difference until shown otherwise). `frame`:
  the two frames differ in size (`frame: ours 0xcc, the original's 0xc8`) and these lines differ only by the
  shifted stack offsets; the `code` hunks left beside them are the real cause (often a variable in a register
  on one side, in a slot on the other). A switch's jump and index tables are data, not code: `tables=equal`
  (or `differ` with the entries that point elsewhere: a case body or the case order differs). grade, asmdiff
  and diffclass read the same extent, so `hunks=0` with equal tables is shape.
- `uv run dcp disasm 0xADDR` - the original code; `uv run dcp dump 0xADDR [LEN]` - its constants and strings.
- `uv run dcp refs NAME|0xADDR` - every use and declaration: the callers say what a parameter means.
- `uv run dcp draft 0xADDR --show` - the analyzer's pseudocode, unchanged: a second reading, not the truth.
- `uv run dcp why 0xADDR|NAME` - everything the ledger knows about an address or a function / data name (names, data, tables).
- `uv run dcp lint` - clang over the units: prototypes (Q7), cross-unit conflicts (M5), calls without one (M7).
  An M5 line is one symbol: its definition (file:line, unit, spelling) and every declaration that disagrees
  or agrees with it; fix every disagreeing one to the definition's spelling (or the definition, when the
  declarations are right). `does not compile in the all-declarations unit` is a header whose declarations
  are not compared at all until it compiles (a missing include, a macro of another header in its way).
  `dcp grade` and `dcp next` lint the changed units themselves, so their Q7 is current.
- `uv run dcp headers conflicts UNIT HEADER..` - before including a header into a unit's head: what it collides with
  (supersedes / duplicate / clash / header / call with the original's pushes / vc6, what only VC6 rejects /
  prototyped, per call `safe` or re-grade) and the functions to re-grade; `--write` makes the include when only
  duplicates are in the way (`--at LINE` places the include when the default line fails the trial). `warning=declaration-set`: re-grade every function of the unit after the include,
  byte ones first (VC6 /O2 moves code by the declaration set alone). `warning=q6`: move the dropped duplicate's
  words into the function's address comment first, or the function falls to draft.

### 2.2 Code below shape (`section=draft`)
Explain every `code` hunk from the evidence and fix the C's meaning: a wrong condition, operand or constant, a
missing or extra statement, a wrong type (signed / unsigned compare, `char` vs `int` load, a struct field at the
wrong offset), a call with the wrong arguments, a loop of another form. Stop when only `fill` / `order` / `regs`
/ `slots` / `sib` / `fpu` / `frame` hunks remain: that is shape (B2). Reconstructing missing statements is always base
work, however long.
- Note `dist` before an edit; after `uv run dcp build`, `uv run dcp grade NAME`: when the distance grew and the
  edit corrected no meaning, revert it (Edit back, or `git checkout -- <file>`). A meaning fix that costs
  distance is kept: say why in the commit message and in the unit's notes.
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
  Functions and data: `uv run dcp rename OLD NEW --why "the evidence"` (project-wide, whole words, names.log;
  `dcp refs` first; OLD may be `0xADDR` / `exe:0xADDR` for the ledger's name). Rename first, then edit: the
  rename writes the new name everywhere and logs it (a name already written by hand in some places is
  completed by the rename, not refused). It prints every changed file with its replacements; a refusal is an
  `error=` record with exit 1 and nothing written: read it, never assume the rename happened. A view
  (`ai_Unk7603a0B`) keeps its name when its datum is renamed (the note lists it): rename it on its own.
  Locals and parameters: edit the function.
- Q3 address literals and Q4 raw access (`*(T *)(p + 0x1c)`, macros built on such casts): a typed field, a
  struct, the symbol (see the hard rule on addresses). A datum the unit reads as another type is a view macro
  with the address comment on its line: `#define NAME (*(T *)&datum)  /* 0xADDR */`, or
  `(*(T *)((char *)&datum + OFF))` for a part of it. `(*(T *)datum)` (no `&`: through the datum's value) is raw
  access and keeps the function at draft.
- Q5 markers (ROUGH, TODO, `@rough`): remove them once the function is written.
- Q6: the address comment says what the function does (`/* 0x4a3000, sends the login reply */`).
- Q7: every call has a prototype (`dcp lint` evaluates it): the callee's prototype lives in its defining unit's
  header `include/<unit>.h`; include that header, never write a second prototype (`dcp refs NAME` shows them).
  When that include does not compile because the unit's head redeclares the header's symbols (its own
  prototype, a partial struct view of a type the header defines, a named object declared `extern GAPDATA`:
  C2371 redefinition, C2198 too few parameters and the like), fix the head (`dcp headers conflicts UNIT HEADER`
  lists what is in the way): include the header, delete the local declarations it supersedes, correct the
  calls and accesses that only compiled against them. Commit
  that on its own, before the function: `<unit>: head includes <x>.h (typing)`; it does not count toward the 8,
  and `uv run dcp check` must show no M1 (an accepted fall, 2.6, is held at its accepted grade). A byte-matched
  function is evidence of what the original declared: when a correction changes its bytes, the correction is
  wrong, not the match, unless the match is no evidence at all (2.6). Find which side is: fix the
  header when its signature or type is the guess, or keep the original's spelling with `@original why` (the
  matched caller as evidence) when the original really called it that way. That spelling stays in the unit
  that needs it, never in a shared header (two headers that disagree can never be included together: M5): a
  cast macro in the unit's head next to the include (`#define d2_MoveObjS ((void (*)(short, short, int))d2_MoveObj)
  /* @original main passes shorts */`), used at those calls. A fall is no way around a conflict (2.6 says when
  one is right), and neither is a copied prototype or a local struct view. A conflict you cannot settle in the
  session: leave it, note `head: include/<x>.h, <symbol> unsettled (<why>)` under **Open work** in the
  unit's notes, and leave Q7 open for the calls it blocks.
- `extern GAPDATA name[]` (`__declspec(align(1)) unsigned char`) is for the unnamed gap blocks only
  (`full_data_<addr>`; it keeps the full rebuild's data packed). An object you name gets its real type and one
  declaration, in its unit's header (section 2.5, gap data).
- `@original why` / `@vc6 why` on a declaration line only with evidence (a byte-matched caller that needs it).

### 2.4 Commit
One function, one commit: `<unit>: <name> shape + readable (match-base)` (`byte + readable` when it got there).
`dcp build` exits 0 first.

### 2.5 Other units, headers, data
- Another unit may change when the meaning needs it and the change is right for it too; a header edit
  recompiles only its includers, and no function anywhere may get worse (`uv run dcp check`: no M1) except by
  an accepted fall (2.6).
- Never rename struct fields or types other units' matched code uses without checking them (`dcp refs`).
- Data errors (D1, D4, D5) are not base work, except the ones your own change causes; `uv run dcp data map UNIT`
  shows a unit's data when a function needs it.
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
  - `uv run dcp check`: no D1 (overlap), no D4 (address order), no M1 (no function got worse); a matched user
    still matching confirms the address (`M.data.site`). A move that breaks one of these was the wrong owner or
    the wrong size: undo it, do not answer it with alignment or padding tricks.
  - An address between two units' blocks with users in both is a boundary question for layout: name and type
    it in place if you must, leave it in the gap block, and note `data: <addr> <name>, owner <A> or <B>
    (<evidence>)` under **Open work** in the unit's notes.

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
Each accepted fall goes through `uv run dcp accept NAME --to shape|draft --why "<the change, why it is closer,
why the match was no evidence>"` (main checkout; `--readability draft` when readability fell too): it lowers
that one function's entry in `ledger/grades.tsv` and records the reason and commit next to it; `dcp check`
then holds the function at the accepted grade. Commit `ledger/grades.tsv` with the change. `dcp promote` (and
the wrap) raise entries only and refuse a fall no accept covers.

## 3. Escalation to the deep queue
When only allocation or scheduling is left (`regs`, `slots`, `order` hunks the classes do not explain away, or
the code is shape and only byte identity is missing), or a generated variant round would be needed:
`uv run dcp escalate NAME "why"`, build, commit `<unit>: <name> -> deep (match-base)`. The reason lists what was
read and tried and the exact remaining hunk (`asmdiff` lines). `dcp escalate` refuses a reason that only names
missing statements: reconstruction is base work. A function you raise to shape + readable that still carries a
stale `@deep` / `@stuck` tag: `uv run dcp escalate NAME --clear`, build again.

## 4. When to stop
A session is **8 functions** raised to shape + readable (or byte + readable) or escalated, then the wrap-up.
Never stop early: a hard function is escalated, not a reason to end; a long queue is not a reason to end;
"it feels long" is no clock. One raise or one escalation is one commit: count the commits and stop at 8
(escalations count). A reconstruction of a big function (~1000 instructions, missing statements) may take most
of a session; that is expected base work, not a reason to escalate it.

## 5. Wrap up
1. Keep the function in progress if it builds and nothing got worse (but by an accepted fall, 2.6), else
   revert; `uv run dcp build` exits 0.
2. `uv run dcp session wrap`: builds, links, checks every target, promotes the grade baseline and prints the
   computed report (errors, byte and readable counts before -> after, `grades changed` per function, renames,
   the next item). It must say `gate: ok`.
3. Update `notes/units/<unit>.md` of every unit you touched: **Open work** first (escalated functions with the
   remaining hunk, near-misses), then the findings (what the functions do, the types and names you derived).
4. Commit: `git add -A && git commit -m "session: match-base wrap (<units>)"` (the baseline and the notes).
5. Final message: the report's first lines (byte / readable before -> after), each function raised or
   escalated with its new grade, the renames, the next `dcp next` item. Stop.
