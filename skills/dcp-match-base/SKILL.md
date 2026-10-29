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
  `dcp <command> -h` explains each one; output is one record per line, `key=value`, addresses `0x%08x`.
- Files stay UTF-8 without BOM with LF line endings; any editing tool will do. Never edit `build/` (derived
  state, the store) or `ledger/grades.tsv` (only `dcp session wrap` / `dcp promote` write it).
- The sources are the state: the address comment on line 1 of every fragment (`/* 0x10001234, what it does */`),
  the declarations in `decl/*.dcl`, renames in `names.log` (written by `dcp rename`), notes in
  `src/<unit>/open.md`. Nothing else; no session log.
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
2. `uv run dcp next` - the base queue, first item first. Read `src/<unit>/open.md` of its unit (its **Open work**
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
- `uv run dcp diffclass NAME` - the hunks and their classes: `fill`, `order`, `regs`, `slots`, `sib`, `fpu`
  (all explained: shape) and `code` (the rest: a meaning difference until shown otherwise).
- `uv run dcp disasm 0xADDR` - the original code; `uv run dcp dump 0xADDR [LEN]` - its constants and strings.
- `uv run dcp refs NAME|0xADDR` - every use and declaration: the callers say what a parameter means.
- `uv run dcp draft 0xADDR --show` - the analyzer's pseudocode, unchanged: a second reading, not the truth.
- `uv run dcp why 0xADDR` - everything the ledger knows about an address (names, data, tables).
- `uv run dcp lint` - clang over the units: prototypes (Q7), cross-unit conflicts (M5), calls without one (M7).

### 2.2 Code below shape (`section=draft`)
Explain every `code` hunk from the evidence and fix the C's meaning: a wrong condition, operand or constant, a
missing or extra statement, a wrong type (signed / unsigned compare, `char` vs `int` load, a struct field at the
wrong offset), a call with the wrong arguments, a loop of another form. Stop when only `fill` / `order` / `regs`
/ `slots` / `sib` / `fpu` hunks remain: that is shape (B2). Reconstructing missing statements is always base
work, however long.
- Note `dist` before an edit; after `uv run dcp build`, `uv run dcp grade NAME`: when the distance grew and the
  edit corrected no meaning, revert it (Edit back, or `git checkout -- <file>`). A meaning fix that costs
  distance is kept: say why in the commit message and in the unit's open.md.
- The original walks pointers, not indices; a `cmp reg, <address>` loop end is an array of structs walked to
  its end (write the array, not address arithmetic). Five fields of one record are one struct, not five
  symbols: separate symbols cost a relocated base each.
- A callee defined above its caller changes the caller's code (registers it leaves alone); the unit's
  `src/<unit>/order` file holds the original TU order: never reorder fragments to make a diff go away.

### 2.3 Readability (`gates=Q...`)
- Q1 / Q2 placeholder names (`ai_Unk4a13e0`, `param_1`, `iVar2`, `DAT_...`): name what you understood.
  Functions and data: `uv run dcp rename OLD NEW --why "the evidence"` (project-wide, whole words, names.log;
  `dcp refs` first). Locals and parameters: edit the fragment.
- Q3 address literals and Q4 raw access (`*(T *)(p + 0x1c)`, macros built on such casts): a typed field, a
  struct, the symbol (see the hard rule on addresses).
- Q5 markers (ROUGH, TODO, `@rough`): remove them once the function is written.
- Q6: the address comment says what the function does (`/* 0x4a3000, sends the login reply */`).
- Q7: every call has a prototype (`dcp lint` evaluates it): the callee's prototype lives in its defining unit's
  header `include/<unit>.h`; include that header, never write a second prototype (`dcp refs NAME` shows them).
- `@original why` / `@vc6 why` on a declaration line only with evidence (a byte-matched caller that needs it).

### 2.4 Commit
One function, one commit: `<unit>: <name> shape + readable (match-base)` (`byte + readable` when it got there).
`dcp build` exits 0 first.

### 2.5 Other units, headers, data
- Another unit may change when the meaning needs it and the change is right for it too; a header edit
  recompiles only its includers, and no function anywhere may get worse (`uv run dcp check`: no M1).
- Never rename struct fields or types other units' matched code uses without checking them (`dcp refs`).
- Data errors (D1, D4, D5) are not base work; `uv run dcp data map UNIT` shows a unit's data when a function
  needs it.

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
"it feels long" is no clock. One raise or one escalation is one commit: count the commits and stop at 8.

## 5. Wrap up
1. Keep the function in progress if it builds and nothing got worse, else revert; `uv run dcp build` exits 0.
2. `uv run dcp session wrap`: builds, links, checks every target, promotes the grade baseline and prints the
   computed report (errors, byte and readable counts before -> after, `grades changed` per function, renames,
   the next item). It must say `gate: ok`.
3. Update `src/<unit>/open.md` of every unit you touched: **Open work** first (escalated functions with the
   remaining hunk, near-misses), then the findings (what the functions do, the types and names you derived).
4. Commit: `git add -A && git commit -m "session: match-base wrap (<units>)"` (the baseline and the notes).
5. Final message: the report's first lines (byte / readable before -> after), each function raised or
   escalated with its new grade, the renames, the next `dcp next` item. Stop.
