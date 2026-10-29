# Layout: declarations and address comments

The layout phase finds the translation units of the original and drafts one source fragment per function.
Its typed state is written by hand in two places: **declarations** (`decl/*.dcl`) for what has no source yet
(unit boundaries, dead bytes, tables, names), and **address comments** in the sources. Both are loaded by
loader rules (`L.decl`, `L.src`) into declared facts; every computed rule re-checks them on every run.

## Declarations (`decl/*.dcl`)

One fact per line:

```
[TARGET:]ADDR[..END] KIND [WORD ...] [key=value ...] -- reason
```

- `ADDR`, `END` are hex; `END` is exclusive. A bare address belongs to the default target (the first
  `[[target]]` of `decompanion.toml`); `exe:0x4a3000` to the target named `exe`.
- The reason after ` -- ` is mandatory.
- `#` starts a comment line. Blank lines are ignored.
- `decl/text.dcl` holds declarations about code sections, `decl/data.dcl` the rest. Each file is sorted by
  (target in config order, address); `dcp decl add "LINE"` inserts a line in place and picks the file.

| kind | form | fact |
|---|---|---|
| `boundary` | `ADDR boundary start\|end tu=NAME [by=leaked\|tag\|guess]` | unit boundary: `start` = the unit's first byte, `end` = the first byte after it; `by` = how the unit got its name |
| `bytes` | `ADDR..END bytes dead` | bytes no function reaches and that are not fill |
| `jumptable` | `ADDR..END jumptable fn=ADDR` | a jump table of function `fn` the walk does not find |
| `idxtable` | `ADDR..END idxtable fn=ADDR` | a byte index table of function `fn` |
| `foreign` | `ADDR..END foreign kind=NAME` | a blob no compiler of the toolchain produced |
| `name` | `ADDR name NAME` | a name for an address without source |
| `fptr` | `ADDR..END fptr` | function pointers stored in a code section |
| `start` | `ADDR start` | a function start the walk does not find; the walk takes it as a root (rule L.decl.start), and what it reaches from there is declared |
| `libunit` | `ADDR..END libunit lib=ARCHIVE tu=NAME` | a library member compiled from source (an import library's code member no installation has): the unit is no game unit (L.unit.extent leaves it out), its fragments lie inside the range and the range outside the game code (L14), and `dcp link` puts its object into ARCHIVE (the generated import library, or a copy of the toolchain's archive under build/link/) instead of the object list, so LINK places it among the library contributions as the original |
| `file` | `ADDR file path=PATH tu=NAME` (data.dcl) | the unit's original file name, at the address of its `__FILE__` string (L.decl checks the image's bytes); the amalgamation compiles the unit under that name, so `__FILE__` matches, and maps diagnostics back to the fragments. An M9 on a `__FILE__` literal prints the line to add |

Examples:

```
0x10008cb0 boundary start by=guess tu=dllmain -- DllMain, Init and Exit: the dll's entry points
0x10008d20 boundary end tu=dllmain -- Init starts the thread procedure at 0x10008d20, the next unit
0x1000f3a0..0x1000f3b8 bytes dead -- unreachable epilogue copy after a noreturn call
exe:0x004a3000 name NetInit -- named by the log string "NetInit failed"
```

Gate errors (check `L.decl`): a malformed line, an unknown kind or key, a missing reason, an unknown target
prefix, an unsorted file, a duplicate key (target, address, kind, first word), an address outside the image,
a range across sections, a code address in `data.dcl` or a data address in `text.dcl`. Each target's store
holds the facts of its own lines only, and an error is a conflict of the target its line names (a line whose
target is unknown: the default target's). `dcp decl add` with `--target NAME` writes a bare address as
`NAME:ADDR` and refreshes that target's store.

Declarations are re-checked every run (`L6`): dead or foreign bytes that walked code covers or a call or jump
reaches, a jump table the walk finds elsewhere or whose `fn` is no start, `fptr` dwords that are not relocated
code addresses, a declared start inside a walked function. Boundaries are checked by `L4` (at a function start,
never inside fill or inside a function) and `L7` (extents overlap, a fragment outside its unit).

## Sources and address comments

```
src/<unit>/head.c        includes, local types, prototypes, leading file-scope data; no function
src/<unit>/f_<addr>.c    one function, plus the file-scope definitions before it in TU order
src/<unit>/tail.c        trailing file-scope data after the last function (optional; milestone 3)
src/<unit>/u_<name>.c    one function the binary does not contain
src/<unit>/order         optional: the TU order of the fragments when it is not the address order (check L12)
include/<unit>.h         public prototypes and extern declarations
```

The amalgamation puts the fragments in address order, then the `u_` files by name. A unit whose translation
unit had another order carries `src/<unit>/order`: `#` reason lines, then every fragment file of the unit once,
in TU order. The order is part of the source: CL compiles a caller differently once a callee is defined above
it, and a declaration must precede its use (the GildeGold.exe migration: 25 of 92 units). `__inline` helpers
are no functions of the binary (no symbol, no address): head.c or any fragment may define them where the TU
needs them, the scan does not count them. A `static` name belongs to its unit: two units may each define one
(check N2 compares statics within their unit only).

A fragment's **first line** is its function's address comment; the file name carries the first address it
lists (check `L11`):

```c
/* 0x10008cc0, starts the server thread */
int __cdecl Init(void)
{
    ...
}
```

Several targets: `/* server:0x10008cc0, exe:0x4a3000, starts the server thread */` (a bare address is the
default target's): the fragment is a fact in the store of every target it lists, at that target's address,
and in no other store. Not in the binary: `/* unlinked, dropped by /OPT:REF */` in `u_<name>.c`. Tags inside the
comment: `@deep why`, `@stuck why`, `@rough`.

Data addresses follow the definition or extern, one per declarator, or stand on the line above a multi-line
table (the same target prefixes):

```c
static int counter = 0;            /* 0x10031270 */
extern int a, b;                   /* 0x10031274, 0x10031278 */
/* 0x10027d08 */
static const char *names[] = {
    "x", "y",
};
```

A placeholder identifier spells an address (`Unk10008d20`, `FUN_10008d20`, `thread_10008d20`): it must name a
start of the target (`L5`). A fragment belongs to the targets its address comment lists, every other file to
all targets; a placeholder is checked in each target its file belongs to whose image holds the number, and a
number no such image holds is reported once, in the default target's store. A fragment's address must be a
function start or lie in unknown code, never inside another function, fill or a table (`L1`). Two definitions
at one address and one name at two addresses (`N2`) are errors (per target). Errors of the source text itself
(a missing address comment, an unknown target prefix) are reported once, in the default target's store.

## Units and evidence

A unit runs from its `boundary start` (else its first fragment) to its `boundary end`, else the next unit's
start, else the end of the game code (the first library byte: LINK places library members after every
object). It is **separated** when both boundaries are at least declared, no open byte (unknown code) and no
C.walk conflict lies inside (milestone 4), else **open**. The last unit's implicit end is derived only when
every function after its start has a fragment of it; otherwise it is open. Undrafted functions (L2) do not keep
a unit open; `dcp layout units` counts them (`undrafted=`).

`L.analyze` computes the evidence `dcp layout next` and `dcp layout unit propose` show: per string literal its
first user (`B-LIT`: in one data section the units of the first users never go backwards, `L3`), what
precedes each function start (`B-FILL`: `cc` linker padding, `nop` compiler alignment, `none`), and leaked
source paths (`B-LEAK`: one unit, one leaked `.c` file, `L8`). Literals reached from data tables are no
evidence (a table's unit is their first user).

Declared dead or foreign bytes (`bytes dead`, `foreign`) inside a unit belong to it (rule `M.bytes.declared`,
R5): a `source` fact {what: dead, unit} over the range, so the byte map gives them the unit, and
`dcp layout units -v` counts them as `dead_bytes=` (explained, not open). A range across a unit boundary is an
error, one in no unit a warning.

Checks added in milestone 4 (warnings: `dcp check --strict` fails on them, `dcp check` does not):
- **L9** an analyzer's function of the game code whose body (its address ranges, which Ghidra's export
  reports) holds one of our starts other than its own entry: the analyzer merged two functions, its draft
  holds both.
- **L10** code inside a unit that a fragment claims but nothing explains: (a) a fragment whose start the walk
  does not know (a declared start in unknown code) and that does not byte-match owns no bytes, its code stays
  open; (b) a byte-matched fragment whose walk runs past its compiled section (rare: R1's tail check).

Checks of source decisions the byte match and the link let pass (errors, rules/layout.py):

| check | rule | criterion |
|---|---|---|
| **A1** | `A1.addr.cast` | an integer literal cast to a pointer type (`(void (*)(void))0x5de470`, `(char *)0x6f242c`, `(T *)(unsigned)0x...`; the cast spells its `*`, a typedef'd pointer name is not recognised) whose value lies in the target's image, in a file of the target; comments, strings and `#if 0` / `#else` text do not count, `#define` bodies do. The relinked image places that object elsewhere. The message names what the facts know there (its name, the symbol containing it, or nothing) and asks for the symbol by name. `(unsigned)&x`, `(char *)&x` take a symbol's address and are not reported |
| **L13** | `L13.data.code` | a data definition or `extern` with an address comment whose address is a known function start (a `start` fact or `func` symbol above declared) or lies inside a known function's extent (walked, placed, byte-matched), unless a jump table, index table or declared fptr range covers it. The message names the function there |
| **L14** | `L14.unit.outside` | a function fragment outside the game code (in the library code) whose unit has a declared boundary and an extent lies outside that extent (inside the game code L7 checks the same) |

## The layout tooling (milestone 4)

Everything a layout session needs; the skill `dcp-layout` (skills/dcp-layout/SKILL.md, installed into a
project's `.claude/skills/` by `dcp init` and `dcp skills install`) runs a session with these commands.

### Drafts for every function: the analyzer

```
uv run dcp setup [--no-analyzer] [--analyzer-force]   # the rules, the analyzer's export when stale, the rules again
uv run dcp report [-v]                                # the analyzer line: drafts, starts only it / only we have, L9
uv run dcp draft 0x10008cc0 --show                    # one draft as the analyzer wrote it
```

The drafts come from the project's analyzer (`[analyzer] plugin`, src/decompanion/analyzers/, docs/architecture.md),
a third-party tool whose opinions are declarations: `ghidra` (the default), `rea` (saved REA `batch_decompile`
results, `file = "..."` or a list) or `none` (no drafts: `dcp draft` writes `@rough` skeletons). `dcp setup` runs
the rules, then the export when its key (analyzer, image sha256, script, our starts) differs from the last one,
then the rules again (only `L.analyzer` and what reads its facts rerun); a second setup does nothing,
`--analyzer-force` exports again, `--no-analyzer` skips the step. A missing installation is one warning line
(`analyzer=ghidra unavailable: <reason>`); setup still exits 0.

Ghidra: headless on the target's binary (project under `build/ghidra/<target>/`, log `headless.log`, the
language from the target's instruction set: `x86` -> `x86:LE:32:default`), the post-script
`data/ghidra/DcpExport.java` creates a function at every start of ours Ghidra lacks (tagged `DCP_SEEDED`: they
are ours, no claim of Ghidra's, no `start how=ghidra` fact), decompiles every function and writes the REA
`batch_decompile` shape plus each function's body (its ranges, for L9). Ghidra and its JDK: `[analyzer] root =`,
`java_home =`, `timeout =` in decompanion.toml (`dcp init` writes what it finds), else `$GHIDRA_INSTALL_DIR` /
`$JAVA_HOME`, else the newest `C:/Tools/ghidra_*` / `C:/Program Files/Eclipse Adoptium/jdk-21*`. On server.dll:
678 functions in ~22 to 30 s (fresh), ~10 s again (the project keeps the analysis).

```
analyzer=ghidra  drafts=678  export=up-to-date  game_functions=311  with_draft=311  analyzer_only=6  ours_only=0  l9=0
  analyzer_only by place: inside=1  unknown.code=5
  analyzer_only=0x10018dc4  name=FUN_10018dc4  size=231  where=unknown.code  game=no
```

### Reading

```
uv run dcp disasm 0x10008cc0 [LEN|..END]     # the original, the ledger's names after every address operand
uv run dcp disasm --ours Init                # our compiled function, relocations named
uv run dcp dump 0x10027d08 0x20 --str        # hex + latin-1 per row with the symbols starting there; --dword --float
uv run dcp refs Init                         # definition, name facts, starts, the draft, refs to / from, source lines
uv run dcp layout starts 0x10008c00..0x10009000
uv run dcp layout literals 0x10008c00..0x10009000     # or a UNIT; default: the game code
uv run dcp layout fptrs deflate                       # or a code range (targets) / a data range (sites)
```

```
   0x10008cc7  68208d0010       push 0x10008d20 <ServerThread>
   0x10008ccc  e8240e0100       call 0x10019af5 <_beginthread>
start=0x10008cc0  how=export,ghidra  callers=0  size=48  extent=0x10008cc0..0x10008ce4  fill=nop  unit=-  drafted=no  analyzed=yes  name=Init
  fn=0x10008d20  unit=-  section=.data  first_used=10  block=0x10027ad8..0x10027d7d  jump=+0xf4
  lit=0x10027d10  section=.data  kind=string  first=0x10008d20  first_unit=-  first_in_range=yes  users=1  data_refs=-  pooled=yes  text=GamePath
  unit_block=server  section=.data  range=0x10027ad8..0x10027d7d  literals=10  interleaves=-
```

`layout literals`: every data address the range's functions refer to (through base relocations when the image
has them, else the walk's operands), with its first user in the whole image and that user's unit; per function
the block of literals it is the first user of and the `jump=` from the highest literal first used by an earlier
function (a big forward jump skips another unit's block; `between=` names the later functions whose literals
fill the gap, with their units: the objects the link order puts in between); per unit the block of its pooled literals (strings and
read-only constants reached from code only) and the units whose blocks it interleaves with. `layout starts`:
every start with every `how` (export, entry, crt, libref, call, tail, immediate, fptr, decl, source, the
analyzer's key), the code sites that reach it, the size to the next start, the walk's extent, B-FILL, the unit,
drafted (a fragment), analyzed (a draft of the analyzer); `LO HI` works as well as `LO..HI`. `layout fptrs`:
every relocated address field outside the code sections whose target is a known function start, in site
order, with the function's name and unit and `delta=` to the previous site of its section (a repeating delta
is the stride of a table of structs).

### Drafting

```
uv run dcp unit new adler32 --range 0x10001000..0x10001130 --by guess --why "zlib adler32: 0xfff1, 0x15b0"
uv run dcp draft --next                       # the function `dcp layout next` shows (or: dcp draft 0xADDR)
uv run dcp unit join A B --why "..."          # B directly after A
uv run dcp unit rename OLD NEW --by leaked|tag|guess --why "..."
uv run dcp rename OLD NEW --why "..."         # one identifier
```

`dcp unit new` = `dcp layout unit propose` (refuses its own L3 / L4 / L7 / L8 errors) + `src/<unit>/head.c`,
`include/<unit>.h` (with its guard) and `src/<unit>/open.md` (Open work first, then findings).

`dcp draft` writes `src/<unit>/f_<addr>.c` (source/draft.py): line 1 `/* 0x10001000, <name> */`, the name the
ledger registers for the address (a declaration, an export, the user entry) else the placeholder
`<unit>_<addr>`; the body is the analyzer's pseudocode with the ledger's names (its dialect in:
Analyzer.rewrite; callees: source, decl, export, entry, library and import names, else the placeholder of the
callee's unit, else `unk_<addr>`; data labels: the ledger's name, else `DAT_<addr>`), or, without a draft, a
`@rough` skeleton holding the disassembly. The prototype goes into `include/<unit>.h`; head.c gets the
analyzer's types header (Ghidra: `#include "dcp_ghidra.h"`, its type names, written into include/), the system
header of every import and C library function it calls (Toolchain.import_header / declaring_header), the header
of every unit that declares a callee, and for the rest a K&R declaration (the analyzer's return type; the whole
prototype for a convention whose decorated name needs the parameters, Toolchain.sized_conventions) or `extern`
(the type from the analyzer's label, Analyzer.data_labels) in a `/* dcp draft: ... */` block. Every other placeholder spelling of the drafted address in src/ and include/ is renamed to the new
name (one address, one name) and its K&R lines leave the dcp blocks.

```
drafted=0x10001310  name=deflate_10001310  unit=deflate  file=src/deflate/f_10001310.c  body=ghidra  size=505  uses=6
  include/deflate.h: undefined4 deflate_10001310(int param_1, ..., char *param_7, int param_8);
  src/deflate/head.c: extern undefined * DAT_1002603c;
  src/deflate/head.c: undefined4 deflate_10001510();
```

`dcp unit join A B` moves B's fragments into A (git mv), merges head.c / tail.c / the headers / open.md, points
the includes at A's header, drops B's start boundary and A's end at it (B's end becomes A's), renames
`B_<addr>` placeholders to `A_<addr>`, builds before and after and exits 1 when a function's code grade or the
error count changed (evidence to keep them apart). `dcp unit rename` moves the directory, header (and guard) and
notes, fixes includes, the boundary lines' `tu=` (and `by=` on the start), the placeholders. `dcp rename`
replaces whole words in code and comments of src/ and include/ (not in string literals or #include lines),
refuses a name that is already an identifier of the code, renames `u_<old>.c` and `name` declarations. All
three append to `names.log`:

```
2026-10-29T14:42:23 0x10001000 func adler32_10001000 -> adler32 by:main why:zlib 1.1.3 adler32 (byte-identical with zlib's source)
2026-10-29T14:42:26 - unit unk_10001130 -> bcast by:main why:by=guess: the unit's one function sends UDP broadcasts
```

The full link classes an unresolved external whose name is a placeholder (or a registered name) of an address
the sources do not define yet as `undrafted`, and leaves an export without a fragment out of the generated .def:
open layout work, not a link error (the link is ok when nothing else is unresolved).

Unlinked helpers (`src/<unit>/u_<name>.c`, first line `/* unlinked, why */`) compile with their unit (M.gen
counts them), get no grade (no address) and are listed by `dcp layout units -v`.

### The session

```
uv run dcp session start     # gate: clean tree, every unit compiles, no error, every link ok; then the overview
uv run dcp session status    # the session clock: started, elapsed, left, over (also line 1 of dcp layout next)
uv run dcp session wrap      # build, link, check, promote (main), the computed report (build/session/report.md)
uv run dcp skills install    # the skills into .claude/skills/ (dcp init does it for a new project)
```

`session start` records the base commit and the start time in `.dcp/session.json` (the session clock: 30
minutes, `dcp session status` and the first line of `dcp layout next` while a session runs) and prints per target the overview: the units, the
next open function, the toolchain level and the analyzer (`analyzer=ghidra  drafts=678`, or `analyzer=none`);
`session wrap` computes the report from git (the base against the working tree), the store and names.log: errors
/ fragments / byte / readable / units before -> after, units declared / joined / renamed, the boundary lines added
and removed, the functions drafted with their grades, the renames, the units touched with their boundary levels,
the next item, the baseline promoted.
