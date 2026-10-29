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
| `start` | `ADDR start` | a function start the walk does not find |

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
include/<unit>.h         public prototypes and extern declarations
```

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
object). It is **separated** when both boundaries are at least declared and no open byte lies inside, else
**open**. The last unit's implicit end is derived only when every function after its start has a fragment of
it; otherwise it is open.

`L.analyze` computes the evidence `dcp layout next` and `dcp layout unit propose` show: per string literal its
first user (`B-LIT`: in one data section the units of the first users never go backwards, `L3`), what
precedes each function start (`B-FILL`: `cc` linker padding, `nop` compiler alignment, `none`), and leaked
source paths (`B-LEAK`: one unit, one leaked `.c` file, `L8`). Literals reached from data tables are no
evidence (a table's unit is their first user).
