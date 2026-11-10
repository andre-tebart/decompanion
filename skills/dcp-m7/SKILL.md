---
name: dcp-m7
description: Run one M7 consistency session of a decompanion project - take the calls without a prototype (dcp lint's M7 lines) one group at a time (one callee, or one owner header included into one unit), give them the true prototype, and read every call the prototype changes against the original's pushes - a call that disagrees is a bug in our C and gets fixed. Option unit=NAME keeps the session in one unit. A session is 8 groups resolved. Use when the user says "m7", "/m7", "dcp-m7", "prototype pass", "consistency pass" or "clear the M7 findings".
argument-hint: "[unit=NAME]"
---

# M7 session: 8 groups, the main checkout

Goal: **no call without a prototype**, and every call agreeing with what the original pushed. M7 (`dcp lint`,
`dcp findings --category contradiction`) lists each call our C makes with no prototype in scope: an undeclared
callee (`NAME (undeclared)`: C89 assumes `int NAME()`), a K&R declaration (`NAME()`: any arguments go), or a call
through an expression with no parameter list (`?()`: a function pointer typed `int (*)()`). The original was
consistent C compiled against prototypes, so each one is a contradiction, and each hides calls the compiler never
checked: a missing or extra argument, an `int` read from a `double` result, a byte pushed where the original
pushed a dword. **Finding those calls is the point of the session**: the M7 count is the measure, the bugs are
the product.

Scope: `$ARGUMENTS` (`unit=NAME` restricts the session to `src/NAME.c`; nothing given: the whole project, the
unit with the most M7 lines first).

Hard rules
- Every tool is `dcp ...` from the project root (`--target NAME` for a target other than the first).
  Every `dcp` of the project runs in the project's daemon, which the first command starts. `dcp <command> -h`
  explains each one; output is one record per line, `key=value`, addresses `0x%08x`.
- Files stay UTF-8 without BOM with LF line endings. Change C text only with a file-editing tool, never with
  shell heredocs, `sed` or quoted script strings (they eat backslashes). Never edit `build/` or
  `ledger/grades.tsv` (only `dcp session wrap` / `dcp promote` / `dcp debt add` write it).
- The sources are the state: address comments, `include/<unit>.h`, the unit's lead comment (`Open:` lines,
  rewritten, never appended to). No notes files, no session log.
- One prototype per function, in its owner's header `include/<owner>.h` (the unit that defines it), spelled as
  the definition. Never write a second prototype in a unit or another header; never a local K&R declaration.
- No grade may fall: `dcp check` fails on M1. A byte-matched caller is evidence of what the original declared:
  when a prototype changes its bytes, the prototype (or our call) is wrong, not the match, except for a
  declaration-set tie-break (section 5).
- Never write an address of the original into code; reference symbols by name.
- Never move a function within or between units, never change a function's meaning without the original's
  instructions as evidence.

## 1. Start

1. `dcp session start`. It is the gate (clean tree, every unit compiles, no error finding, the link ok). On
   `gate: FAIL` fix what it lists (or revert), commit, start again; an `obligation=toolchain.*` /
   `obligation=libs.archives` line is a human decision: stop and hand it to the user.
2. `dcp lint` and note the total (`m7=N` in its first line): the session's starting count.
3. Group the M7 lines (`M7 src/<unit>.c: <callee> at line N`) by unit and callee, count each group. With a
   `unit=` option keep that unit's lines only; without, take the unit with the most lines.
4. Read that unit's lead comment (`src/<unit>.c`), especially its `Open: head:` / `Open: not included yet` lines:
   they name the headers that are held back, the declarations in the way and the calls known to disagree.

## 2. Picking a group

A group is the unit of work and of the count: **one owner header included into one unit** (all its callees'
M7 lines in that unit at once), or **one callee** when its fix is not an include (a K&R view in a header, a
function pointer type, a CRT function). Take the group that clears the most lines; between equals, the one whose
header the lead comment names as held back for the fewest reasons. For each callee: `dcp refs NAME` names its
definition (`definition=src/<owner>.c:LINE`) and every declaration of it.

## 3. Fixing a group

### 3.1 The prototype
- The owner's header holds the prototype, spelled as the definition (parameter types and return type), with the
  address comment (`/* 0x4fe140 */`). Missing: add it from the definition. A K&R `T NAME();` in the owner's
  header: replace it with the definition's parameter list. Header and definition disagree: the definition is the
  authority unless byte-matched callers in several units contradict it (then read the definition against the
  original: it may be the guess).
- A CRT callee (`sqrt`, `fabs`, `memcpy`, `_ftol`, `toupper`, ...): include the CRT header (`<math.h>`,
  `<string.h>`, `<ctype.h>`, `<stdlib.h>`), never a hand-written prototype. A CRT object declared by hand
  (`extern ... _pctype`, `__mb_cur_max`) goes the same way.
- A callee with no definition in our sources (an import, a library member): the SDK or CRT header that
  declares it.
- `?()`: find the expression (`dcp fn` of the function at the line). It is a function pointer: a struct field, a
  table, a cast. Give its type the parameter list: the functions stored into it (`dcp refs` of the table or
  field; the registration calls) and the original's pushes at the indirect call agree on it. A table of handlers
  of one signature gets a `typedef` in the owner's types header, used by the field and the table.

### 3.2 The include
1. `dcp headers conflicts UNIT HEADER` lists what the include collides with: local prototypes it supersedes
   (`duplicate`), K&R views and local struct views it redefines (`clash`), calls the new prototype changes
   (`call ... with the original's pushes`), VC6-only errors.
2. Remove what it supersedes: the unit's own copies of the header's prototypes and types, its K&R views,
   its `extern` copies of the owner's data. Keep a local declaration only when the header has no such symbol.
3. `dcp headers conflicts UNIT HEADER --trial` compiles the unit with the include and re-grades it: every
   `fn=... now=... trial=...` line is a function whose code the include changes; `m1=yes` is a fall. Then
   `--write` (or add the `#include` in the head region by hand, after the last include).
4. A header that does not compile in the unit (a macro of another header in the way, a type it needs that the
   unit spells another way): fix the head (include the types header first, drop the local view in favour of the
   shared type). When the conflict cannot be settled in this session, leave it: one line `Open: head:
   include/<x>.h, <symbol> unsettled (<why>)` in the lead comment, and take another group. A group you leave does
   not count.

### 3.3 Every changed call: read the original's pushes
`dcp build` (it exits 0 only when everything compiles), then every compile error and every function whose grade
moved (build's summary, `dcp check`'s M1 lines, the trial's `fn=` lines) is a call to read. For each:
- `dcp asmdiff CALLER --at 0xSITE --context 12` (or `dcp disasm 0xCALLER --range +0xA..+0xB` around the site): count the pushes
  before the `call` and the `add esp, N` after it (cdecl: N / 4 arguments; a `push` of `movzx`/`movsx` /
  `push 0xff` vs `push -1` gives the width and signedness of a parameter), and what is read after the call (eax
  used, `movsx eax, ax` for a short result, `fstp` for a float / double result, nothing for void).
- Decide which side is wrong:
  - **Our call disagrees with the original's pushes** (missing or extra argument, an argument in the wrong
    position, an `int` read of a float result, a cast that drops width): our C is wrong. Fix the call to what the
    original passes. This is a **bug fix**: say what the call did before and what it does now.
  - **The original's pushes agree with the prototype**, our call only compiled because there was none: fix the
    call (also a bug fix when it changes what is passed).
  - **The original's pushes disagree with the definition's prototype, consistently across this unit's
    byte-matched callers**: the original TU was compiled against another declaration. Keep the header as it is;
    add a cast macro in the unit's head next to the include, with the evidence:
    `#define net_SendKeyI ((int (*)(int, char *))net_SendKey)  /* @original: the callers here push the key
    as an int and read the return (byte-matched net_QueueOrder) */`, and use it at those calls (the suffix
    names the difference: `I` int, `S` short, `K` K&R, `H` handle / result kept). Never a second prototype,
    never in a shared header.
  - **The header is the guess** (the definition was drafted from the header, the original's definition reads
    its parameters otherwise: `dcp disasm` of the callee): fix the definition and the header together, and read
    every caller in every unit (`dcp refs NAME`).
- Stale `@original` comments that the new header made untrue (`against net.h's void view` when net.h now says
  `int`): correct them while you are there.

### 3.4 Gate before the commit
- `dcp build` exits 0; `dcp lint`: the group's lines are gone and nothing new appeared (an M5 line from your
  change is fixed now: the header and the definition must agree).
- `dcp check`: no M1, except a tie-break (section 5). A fall that is not a tie-break means a wrong prototype or a
  wrong call: find which (3.3) and fix it. Never accept it, never `dcp debt add` in this session.

### 3.5 Commit
One group, one commit. The message names the unit, the header or callee and the count, in the project's style:
- `m7: ui includes time.h (tm_AddTime, tm_CompareTime, tm_Title: 412 calls prototyped; 6 duplicates dropped)`
- A group that fixed calls: prefix `m7 bug:` and list each fixed call in the body, one line each:
  `ui_ShowTip 0x567c00: tm_AddTime(&end, r + 8) passed 2 of 4 args (mins / secs read from stale stack); now
  tm_AddTime(&end, util_RandomU(4) + 8, 0, 0) per the original's pushes 0x567c92..0x567ccd`.
  `git log --grep "m7 bug"` is how the user finds them: never fix a call without saying so.
A message of more than one line goes through a file (`git commit -F <file>`). `git status` clean before the next
group.

## 4. When to stop
A session is **8 groups** committed (each must lower the M7 count), then the wrap-up. Stop early only when the
scope has no M7 line left, or every remaining group is left as `Open: head:` with a reason. Never stop because a
group is big: a large header include into a big unit is one group, however long.

## 5. Tie-breaks
VC6 /O2 can change a function's bytes by the declaration set alone (an include, a typedef nothing uses). `dcp
build` probes the unit of a fall (`dcp headers probe UNIT` by hand, recorded in `ledger/tiebreak.tsv`: commit it).
A function whose own text did not change and whose bytes move under the probe is no fall: M1 prints `tie-break: N
functions moved (HEADER)`, and promote takes it. Keep the include. Any other fall is yours to fix.

`dcp headers sample NAME` measures one function more widely than the unit probe (random unused declarations
and layout-preserving member changes inside the include chain); use it when a fall is not explained by the probe.

## 6. Wrap up
1. Keep the group in progress only if it builds, lints and checks clean; else revert it.
2. `dcp session wrap`: builds, links, checks, promotes the grade baseline, prints the report. It must say
   `gate: ok`. Commit the last group first (it promotes nothing with uncommitted src/, include/ or decl/).
3. Rewrite the lead comment of every unit you touched to its current state: drop the `Open: head:` / `Open: not
   included yet` entries you settled, keep one line per one still open with its reason. No dated or "this
   session" lines.
4. Commit: `session: m7 wrap (<units>)`.
5. Final message, short: M7 before -> after (`dcp lint`'s `m7=`), the groups committed, **every bug fixed** (one
   line each: function, address, what the call did, what it does now), grade changes from the wrap report,
   the groups left open and why, and the next group you would take. Stop.
