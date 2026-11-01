---
name: dcp-layout
description: Run one layout session of a decompanion project - for 30 minutes (the session clock) find translation-unit boundaries and draft source for every function of each unit in address order, then wrap up. Use when the user says "layout", "/layout", "dcp-layout", "start a layout pass" or "layout round".
---

# Layout session: 30 minutes, the main checkout

Goals, in order: (1) find the unit boundaries (one file `src/<unit>.c` per translation unit of the
original); (2) draft C for every function of each unit in address order, no gaps (a hard or big function gets a
`@rough` draft, it is never skipped); (3) quick byte fixes only.

Hard rules
- Every tool is `uv run dcp ...` from the project root (`--target NAME` for a target other than the first).
  First check `uv run dcp serve --status`; when no daemon runs, start one with `uv run dcp serve` (it
  detaches and returns) and leave it running: every `uv run dcp` of the project runs in it, and without it
  every command fails ("no daemon runs ... start it with `dcp serve`"). A worktree needs its own (`dcp serve`
  there).
  If `uv run` fails with "failed to remove file ...dcp.exe" (access denied), an old daemon holds the exe: run
  `uv run --no-sync dcp serve --stop`, then retry.
  `dcp <command> -h` explains each one; output is one record per line, `key=value`, addresses `0x%08x`.
- Files stay UTF-8 without BOM with LF line endings; any editing tool will do. Never edit `build/` (derived
  state, the store) or `ledger/grades.tsv` (only `dcp session wrap` / `dcp promote` / `dcp accept` write it).
- The sources are the state: the address comment directly above every function's definition
  (`/* 0x10001234, what it does */`), the declarations in `decl/*.dcl` (unit boundaries, dead bytes, starts,
  names; always with a reason after ` -- `), renames in `names.log` (written by the dcp commands), the unit's
  current state in its lead comment (the first comment of `src/<unit>.c`: what the unit is, then its open
  questions as `Open:` lines). The lead comment is a brief snapshot, rewritten, never appended to: no dates, no
  history, no session log (git is the history). Nothing else: no notes files.
- A unit is one file, `src/<unit>.c`, in the original's TU order: the head region (includes, types, prototypes,
  the dcp declaration block: everything above the first function), then the functions with the data between
  them. `uv run dcp fn NAME|0xADDR` prints one function with its file and lines (`at=src/<unit>.c:FIRST-LAST`):
  read a function that way, and edit it in place.
- Explicit or computed: a boundary is a declaration with the evidence as its reason, or it is open. Never write
  a guess without saying it is one (`--by guess`).
- No byte-matched function may fall (`dcp check` fails on M1). `dcp build` exits 0 before every commit.

## 1. Start

1. `uv run dcp session start --kind layout`. It is the gate (no open toolchain or libs obligation, clean working tree, every
   unit compiles, no error conflict, the link ok) and prints the overview: units, the first open function
   (`next=`), the toolchain level, the analyzer (`analyzer=ghidra  drafts=678`), then the status tail (`---
   dcp status`: the phase and the open obligations in order, one `obligation=` line each with what is missing,
   the evidence and the command that resolves it). On `gate: FAIL` fix what it lists (or revert), commit, and
   start again; do not work on a failing gate. An `obligation=toolchain.*` or `obligation=libs.archives` line
   under the FAIL is a human decision (the compiler, linker, root, flags, static libraries): never declare it
   yourself; stop and hand the line to the user (`uv run dcp status`, `uv run dcp toolchain` and `uv run dcp
   libs candidates` show the evidence; `dcp toolchain declare` / `dcp libs declare` resolve it, always with
   `--why`). An open `obligation=analyzer` does not block the session: mention it in the wrap-up. The drafts
   come from the project's analyzer (`[analyzer]` in
   decompanion.toml, a third-party tool `uv run dcp setup` runs when its export is stale); with `analyzer=none`
   or `drafts=0` every draft is a `@rough` skeleton (`uv run dcp report` says why: `export=`, and setup prints
   `analyzer=ghidra unavailable: <reason>` when the tool is missing).
2. The clock started with the gate: `dcp session start` recorded the start time, and from now on the first
   line of every `uv run dcp layout next` is the clock (`session=running  elapsed=12m  left=18m  over=no`;
   `uv run dcp session status` prints the same line). It is the only clock of the session: no timer, no `date`
   checks, no estimating. Until a clock line says `over=yes` the session is not over. The 30 minutes bound the
   work loop only: the wrap-up has no time limit. The only failure is ending the turn before `over=yes` (a
   complete layout is the one exception, below), not the clock running out mid-function.
3. Read the lead comment of `src/<unit>.c` of the unit the `next=` line names (its `Open:` lines) when it exists.

## 2. Work loop (until the clock says over=yes)

Always work the first open function; never skip one, never stop early, never end the turn to wait.

1. `uv run dcp layout next` - first the clock line (`over=yes`: go to section 5 now), then the first function of
   the game code without a source, with its evidence: its
   start (`how=`: export, call, tail, immediate, fptr, decl, the analyzer's key such as `ghidra` ...), its
   callers and their units, the fill before it, the literals it uses first, leaked source paths, whether the
   analyzer has a draft (`analyzed=`; `uv run dcp draft 0xADDR --show` prints it unchanged).
   - It lies in a unit (`unit=NAME`): go on with step 2.
   - It lies in no unit (`unit=-`): decide the unit first (section 3): extend the previous unit (move its end
     boundary: edit the `boundary end` line in `decl/text.dcl`, keep the file sorted) or declare a new one with
     `uv run dcp unit new NAME --range 0xSTART..0xEND --by guess|tag|leaked --why "the evidence"`. A placeholder
     name is fine (`unk_10001234`); rename it when evidence turns up (section 4). When the end is not known
     yet, give only the start (`--range 0xSTART`): the unit runs to the next unit or the end of the game code
     and stays open; declare its end as soon as evidence shows it.
   - `kind=unknown` (code no start explains): find the start (`uv run dcp disasm 0xADDR`, `uv run dcp layout
     starts LO..HI`) and declare it (`uv run dcp decl add "0xADDR start -- why"`), or declare dead bytes (section 3).
2. `uv run dcp draft --next` - inserts the function into `src/<unit>.c` in address order (before the unit's
   next function, else at the end; `file=` and `uv run dcp fn 0xADDR` show where): the address comment
   `/* 0x10001234, <unit>_10001234 */` directly above it, the body from the analyzer's draft with the ledger's
   names (callees that the ledger names are spelled that way, others as placeholders `<unit>_<addr>` /
   `unk_<addr>`, data as `DAT_<addr>`), the prototype in `include/<unit>.h`, the includes and K&R declarations
   it needs in the unit's head region. Without a draft it writes a `@rough` skeleton with the disassembly as a
   comment: fill it from `uv run dcp disasm 0xADDR`.
3. `uv run dcp build` - compile. Fix what the compiler says at the line it names (section 2.1). Then give the
   function a description in its address comment (`/* 0x10001234, sends the login reply */`) and better names
   for what you understood (section 4).
4. `uv run dcp grade <unit>` - grades and distance per function. Only quick byte fixes (the original's size, a
   few bytes off, one local cause in `uv run dcp asmdiff NAME`); at most two attempts, then leave it: the
   grade and `dcp asmdiff` show the near-miss to the next session.
5. Commit every few functions: `git add -A && git commit -m "<unit>: drafts 0x10001130..0x10001510 (layout)"`
   (`dcp build` exits 0 first).

### 2.1 Making a Ghidra draft compile (VC6, C89)

Ghidra-specific advice: the analyzer is Ghidra (`analyzer=ghidra`).
What `dcp build` typically says about a fresh draft and what to do:
- `'sockaddr' : undeclared identifier` and the like: Ghidra writes struct types without `struct`; write
  `struct sockaddr`. Windows types are the common case: Ghidra spells the struct tag (`_EXCEPTION_POINTERS`,
  `_MEMORY_BASIC_INFORMATION`), windows.h's typedef drops the underscore (`EXCEPTION_POINTERS`,
  `MEMORY_BASIC_INFORMATION`); a C2065 on such a name in a signature means: use the typedef.
- `left of '._2_4_' must have struct/union type`: Ghidra's partial access to a field; rewrite it as a cast of
  the field's address or as the real fields (`*(int *)&local_20.sa_data[2]`), or use the real struct.
- `illegal indirection` on a `DAT_` name: the datum is a pointer or an array; change its declaration in the
  `/* dcp draft: ... */` block of the unit's head (`extern char *DAT_10027a2c;`). Types of data are a guess until the
  match phase places them; keep them minimal.
- `in_EAX`, `unaff_ESI`, `extraout_ECX`: registers Ghidra could not tie to a parameter; read the call sites
  (`uv run dcp refs 0xADDR`, `uv run dcp disasm CALLER`) and make them parameters or locals.
- `CONCAT`, `SUB`, `ZEXT`, `SEXT` macros, `undefined4`, `uint`, `byte`, `code` come from
  `include/dcp_ghidra.h`; they compile, they are not readable: replace them as you understand the code.
- A call through a function pointer `(*(code *)x)()` compiles; give the pointer a real type when you can.
- Never replace a compiling draft by a `@rough` skeleton to make the gate pass: a gate error that a worse draft
  makes go away is a tool bug; report it and leave the draft in place.
- C89: declarations at the top of a block; no `//` comments in new code; no `bool`.
- Never write a second prototype for a name: `uv run dcp refs NAME` shows every declaration. A function of
  another unit is declared by including that unit's header; an undrafted one by the K&R line `dcp draft` wrote.
- A function of a known library (zlib announces itself by its version string, `1.1.3`; a CRT-like routine by
  its shape) is best written as that library's own source: it often byte-matches at once (zlib's adler32 did,
  where Ghidra's unrolled loop did not).
- Quick byte fixes `dcp asmdiff NAME` shows: Ghidra splits one store into byte stores (`char on[4]` with four
  assignments where the original writes one dword: write `int on = 1;` and pass `(char *)&on`), a signed /
  unsigned compare, the operand order of a commutative operation.
- Warnings that are expected while a unit is half drafted: `M7 call without a prototype` (the K&R lines),
  link `unresolved undrafted=` (placeholders of functions and `DAT_` data the sources do not define yet, exports
  without a source): open work, not errors. `unresolved data=` / `other=` are errors: a real name nothing
  defines (give it an address comment or a definition).

## 3. Boundaries: the evidence, strongest first

Proof is often impossible; spend effort only on contrary evidence. Each kind and the command that shows it:
1. **leaked** source paths (an `__FILE__` in an assert or log string): `leak` lines of `uv run dcp layout next`,
   the `leaks=` column of `uv run dcp layout units`; one unit, one leaked `.c` file (L8). Names the unit:
   `--by leaked`.
2. **literal order**: string literals and constants sit with their first user in link order, so the units'
   literal blocks do not interleave. `uv run dcp layout literals 0xLO..0xHI` (or `UNIT`): per function the
   block of literals it uses first and the `jump=` from the earlier functions' highest literal (a big forward
   jump skips another unit's block: a boundary candidate; a backward jump: this function belongs to an earlier
   unit's block; `between=` names the later functions, and their units, whose literals fill the gap: the
   objects the link order puts in between, even when their code sits far away), per unit its block and
   `interleaves=`. A contradiction is the error L3.
3. **fill**: `uv run dcp layout starts 0xLO..0xHI`, column `fill=`: `cc` is the linker's padding between two
   objects (a boundary right there), `nop` is the compiler's alignment inside one object (proves nothing).
4. **registration tables**: a table of function pointers in data usually lists the functions of one unit.
   `uv run dcp layout fptrs UNIT` (or a code range: the functions pointed to; a data range: the sites) lists
   every function pointer in data with its function's name and unit; a repeating `delta=` is a table of
   structs (zlib's configuration_table: stride 12, deflate_stored / deflate_fast / deflate_slow).
5. **codegen coupling**: a function that matches only with a neighbour's code above it (found in the match
   phase): the two are one unit.
6. **guess**: what the functions do (`--by guess`, the reason says why).

Commands: `uv run dcp unit new NAME --range 0xSTART..0xEND --by ... --why "..."` (runs L3 / L4 / L7 / L8 on the
proposal first and refuses errors, writes the boundary lines and the files `src/NAME.c` (its head),
`include/NAME.h`); `uv run dcp layout units -v` (every unit: range, status, boundary
levels, open bytes, undrafted functions, dead bytes, unlinked helpers, L10); `uv run dcp layout unit propose`
(the check without the files); `uv run dcp decl add "LINE"` (one declaration, inserted in order).

Unexplained bytes: code no function explains inside a unit keeps it open (`open_bytes=`). Either it is a
function (declare its start: `0xADDR start -- reached only through a table at 0x...`) or it is dead
(`uv run dcp decl add "0xSTART..0xEND bytes dead -- unreachable copy of the epilogue after a noreturn call"`:
the unit owns the bytes, R5). L10 (a warning) names walked code a byte-matched function does not contain.
A helper the original inlined everywhere (so no address) stands in its unit's file with the address comment
`/* unlinked, why */` directly above it; it compiles with the unit and gets no grade.

## 4. Joins and renames

- **Join** as soon as evidence proves two units are one (a function that needs its neighbour's code, literal
  blocks that interleave, one leaked file): `uv run dcp unit join A B --why "..."` (B directly after A). It puts
  B's head lines that A lacks into A's head and B's functions after A's in `src/A.c`, merges the headers and the
  notes, rewrites the boundary lines and B's placeholders, builds before and after and refuses (exit 1) when a
  grade or the error count changed - that is evidence to keep them apart: revert
  (`git checkout -- . && git clean -fd src include notes`). Commit
  `<A>: join <B> (layout)`.
- **Unit rename** when a stronger name source turns up (`leaked` > `tag` > `guess`):
  `uv run dcp unit rename OLD NEW --by leaked|tag --why "..."` (its file and notes, header and guard, includes,
  boundary lines, placeholders `OLD_<addr>`, names.log). Commit `<old> -> <new> (layout, <by>)`.
- **Function and data names**: `uv run dcp rename OLD NEW --why "..."` (whole words in src/ and include/,
  refuses a collision with an `error=` record and exit 1, lists every changed file, names.log). Rename a placeholder as soon as the meaning is clear; `uv run dcp refs NAME`
  first shows every use. Several names: `uv run dcp rename OLD1 NEW1 OLD2 NEW2 ... --why "..."` (or `--from FILE`)
  rebuilds once for all of them.

## Headers

- The prototype of a function lives in its defining unit's header `include/<unit>.h` (`dcp draft` puts it
  there); other units include that header. Never write a second prototype elsewhere.
- Never change other functions' bytes: no edits to types, macros or declarations another unit's matched code
  depends on; add, do not change (an alias type, a second view, a cast macro local to the unit).
- Never rename struct fields or types in a layout session.

## 5. Wrap up (when the clock says over=yes)

1. Finish or revert the function in progress; `uv run dcp build` exits 0.
2. `uv run dcp session wrap`: builds, links, checks every target, promotes the grade baseline and prints the
   computed report (check before -> after, units declared / joined / renamed, functions drafted with their
   grades, renames, the units touched with their boundary levels, the next item). It must say `gate: ok`.
3. Rewrite the lead comment of every unit you touched to its current state (a few lines): what the unit is,
   then one `Open:` line per boundary doubt you leave open, with its lead. Drop what is settled; never add a
   dated or "this session" line. The evidence for a boundary goes into its decl line's reason. Rough functions
   and near-misses need no note (`@rough`, the grades). Git and the report are the record.
4. Commit: `git add -A && git commit -m "session: layout wrap (<units>)"` (the baseline `ledger/grades.tsv`).
5. Final message: the report's first lines (check before -> after, units, functions drafted), the open
   boundaries with their leads, the next item. Stop.

A complete layout: `dcp layout next` prints `nothing open` and every unit of `dcp layout units` is separated
and named by more than a guess, or no lead is left: wrap up at once (this is no early stop) and say
`layout complete` in the final message.
