# Match: build, compare, grades, the full link

The match phase compiles the sources, compares every compiled function with the original's bytes, grades
each function, and links the whole target. The sources stay the typed state: an address comment is a
declared candidate (`L.src`), the match rules verify it and emit facts above the declared level.

## Build (`dcp build`)

```
uv run dcp build [--target T | --all-targets] [--force]
uv run dcp fn NAME|0xADDR         # one function: its file, lines (its span) and text
```

One translation unit per unit file: `src/<unit>.c`, compiled as it stands, with the target's define
`DCP_TARGET_<name>` (plan.rs): a function of some targets only stands under `#if` on
their macros. A function belongs to the targets its address comment lists (a bare address: the default
target), an unlinked one to every target; a unit without a function of the target is no unit of it. The
compiler's diagnostics name the unit's file and its physical line (a `#line` name or pin of the file mapped
back).

Flags: the target's `cflags`, then the cflags of the first `[[toolchain.unit]]` whose `glob` matches the unit
name (optionally restricted by `targets = [...]`; a `reason` is mandatory):

```toml
[[toolchain.unit]]
glob = "zlib*"
cflags = ["/Ob1"]
reason = "zlib's own makefile flags"
```

Include directories: `include/` (a quoted include also resolves beside the file, in `src/`); the toolchain adds its own headers (VC6: `VC98/Include`,
`[toolchain] include_dirs` first) and libraries (`VC98/Lib`, `[toolchain] lib_dirs` first).

A unit is stale iff its source hash (the file's text), its flags hash or its include hash (the contents
of every file of its actual include set) differs from its `tu` row in the store. The include set comes from
the preprocessor (VC6: `CL /E`, the `/P` listing on stdout, its `#line` directives) and is cached per (source
hash, flags hash, listing hash of every include directory); a changed file of the set makes the unit stale and
the set is read again with the compile. So an edited header recompiles exactly its includers. Stale units
compile one `CL.EXE` per unit in a thread pool (`cpu_count`); objects are stored by content as
`build/obj/<sha256>.obj`. A failed unit keeps its row with `ok=0`, its log and diagnostics: it is a `build`
fact with `ok=false` and a gate error, and compiles again only when an input changes. Nothing reads an mtime.
A second `dcp build` with nothing changed compiles nothing and runs no rule.

Without the toolchain installed nothing compiles; the units are reported as warnings, not errors.

## Compare and the code rules

| rule | level | criterion |
|---|---|---|
| `M.compile` | proven | one `build` fact per unit (ok, object, flags, diagnostics, stale); a failed or never compiled unit is an error, a stale one a warning; `M.gen`: every function of the object has an address comment of the target in the unit's file and vice versa |
| `M.match` (R1) | proven | the function's section bytes equal the image's at the function's address with our relocated fields masked; the original does not continue after our end (only fill up to the next start); for a dll every absolute relocation site of ours is a base-relocation site and the counts agree (`relocs 7/7`). Emits a `symbol` func (to the last non-fill instruction or the first switch table) and a `source` fact (what: match) |
| `M.draft` (R2) | ≤ declared | a compiled function that is no match owns the walk's extent: a `source` fact (what: draft) with why it differs |
| `M8.reloc` | proven | for a match, or a dll function whose absolute sites the aid lines up, at every relocation site where our instruction and the original's at the same offset are the same (equal size, equal outside our relocated fields): M8 our relocation names X registered elsewhere than the original's site holds; M9 string literal bytes differ; M10 float constant bits differ |
| `M.data.site` | proven | a byte-matched function's relocation confirms a data definition's address comment |
| `M.data.content` | proven | the definition's initialised bytes (relocated fields and possible alignment padding masked) equal the image's at the declared address and occur nowhere else in initialised data |
| `M.data.draft` | declared | every other data definition with an address |
| `D.data` | — | D1 extent overlaps the next symbol (an error when even the least size reaches it, a warning when only alignment padding may: COFF has no sizes, an object's size runs to the next symbol), D4 definition order vs address order per unit and section kind (in the unit file's order, a header's definitions at the line that includes it), D5 a tentative definition in uninitialised data, D6 a pointer-table entry refers elsewhere than the original's |

A data extent claims only the bytes the definition certainly owns (`least_size`).

### Data tooling: `dcp data map`, `dcp data fix`

`dcp data map` lists every unit's data (definitions per section, proven, conflicts); `dcp data map UNIT` its
declarations in address order with section, size, room up to the next symbol, level and conflicts.

`dcp data fix [--check D5,D1,D4] [--unit U] [--write]` answers the data checks with source rewrites
(the core's datafix.rs): D5 `T x;` -> `= 0` / `= {0}` at the end of the declarator; D1 shrinks an array's first
dimension to the room before the next symbol (externs with the old dimension follow), only for D1 errors and
only when it shrinks; D4 keeps the longest run of a unit's definitions already in address order and moves
every other one in front of its successor by address (a non-static one moving down leaves `extern T x;` for
the uses above; one that would move above a type, macro or declaration it uses is left for a human). Without `--write` it lists the edits and the cases left for a human, with their reason.
With `--write` it first compiles the sources (the checks read the objects), then trial-compiles each unit with
its edits (build/obj/trial/, no store, no sources touched) and compares its functions: a unit keeps all its
edits when it compiles and keeps every byte match, else each edit group is tried alone in parallel and only
the groups that keep the unit whole are written; then one build and refresh confirm the batch (it goes back
whole if a byte match was still lost). gildegold, 2026-10-30: 616 data errors -> 9, every byte match kept,
92 s for the whole run from scratch.
| `M.lint` | — | M6 clang error inside a unit, M5 declaration conflict across units, M7 call without a prototype (warn); from `dcp lint` |
| `M.flags.proven` | proven / declared | per flag group of the last probe: proven when anchors from ≥ 2 units distinguish the flag |

## Grades

Two grades per (function, target), computed by `G.grade` (the core's grade.rs, readability.rs) into `grade` facts:

**code** `draft → shape → byte`
- B1 byte: M.match holds.
- B2 shape: every differing hunk of the instruction diff is `fill`, `order` (same multiset), or explained by
  the ISA (`regs`, `slots`, `order` after a register renaming, `sib`, `fpu`; x86: `[esp + N]` is compared as it
  was at the hunk's start, so a store moved across a `push` / `pop` is `order`, or `slots` when its slot changed
  too), or `frame`; or the leftover `code` hunks are
  the same multiset on both sides; or one bijective register / slot renaming explains the whole function; and
  the switch tables, when both sides have them, are equal.
- B3 draft: otherwise, or no compiled object.

What the diff compares (the core's diffclass.rs, the one reading `G.grade`, `dcp asmdiff` and
`dcp diffclass` share): our instructions up to the first compiler label after the code (CL's switch tables),
and the original over the function's extent (the code walk's, else the source extent `L.src.extent`) cut at
its first switch table. A walk of the function's slot (up to the next known start) finds the jump tables its
indirect jumps read and their byte index tables; a function the walk did not reach owns its tables by
contiguity, and they are no code. The tables of both sides are compared as data: each relocated entry of ours
by the instruction it points to (the same instruction, the same aligned hunk, or the same block up to its `ret`
/ `jmp`: a case moved with its code), every other byte (index tables, fill) by value. Equal tables are
reported (`switch tables equal (4 entries, 19 index bytes)`, never a hunk); differing ones are a `table`
difference that keeps the function from shape. `dist` gives the original's code size without the tables.

The `frame` class: when the two prologues allocate frames of another size (`sub esp, 0xcc` against `sub esp,
0xc8`), one slot more or less shifts every stack offset above it and the plain diff is one long `code` hunk.
Then the instructions are aligned again with the stack offsets and the frame size masked; the lines that differ
only in their stack offsets, each by 0 or by the frame delta (the frame sizes by exactly the delta), are `frame`
hunks of their own, everything else is classified as usual. The frame-aligned verdict is taken when the plain
one is no shape; `dcp diffclass` says `frame: ours 0xcc, the original's 0xc8` above its hunks. A frame that
differs only by the constant shift is shape (B2 tolerates stack layout); a variable kept in a register on one
side and in a slot on the other still leaves `code` hunks next to the `frame` ones.

**readability** `draft → readable`: Q1 the name is no placeholder, Q2 no placeholder identifier in the
definition, Q3 no image address literal, Q4 no `*(T *)` cast or macro hiding one (a view macro with its address comment is no raw access: `(*(T *)&datum)` or `(*(T *)((char *)&datum + OFF))`; `(*(T *)datum)` is; the message states the view form), Q5 no ROUGH / SKELETON /
TODO / FIXME / XXX / `@rough`, Q6 the address comment (or another comment) describes the function, Q7 every call
goes through a prototype (only for units the last `dcp lint` parsed; otherwise not evaluated, and `dcp grade`
says so), Q8 our code is at least half the original's size (a stub or an unfinished body is no readable function).

**unit**: code = the lowest of its functions; readable only when every function is and the unit's name has an
origin other than `guess` (`boundary start ... by=leaked|tag`).

The distance (differing instructions, differing bytes, our size vs the original's code size) is part of the
grade fact and of every report; it is not a gate.

```
uv run dcp grade                  # the matrix and the unit table
uv run dcp grade UNIT             # its functions, failing rules with evidence
uv run dcp grade NAME|0xADDR      # one function: grades, failing rules, hunks, distance
uv run dcp asmdiff NAME [--regs a=b,...] [--all]   # instruction diff, ours '-' / original '+'
uv run dcp diffclass NAME         # the hunk classes and the verdict
```

## The level ladder

`@deep why` and `@stuck why` in the address comment: `dcp escalate NAME "why"`, `dcp stuck NAME "why"`, either
with `--clear`. `escalate` refuses a reason all of whose clauses speak only of missing or unwritten statements
(reconstruction is base work). `dcp build` removes the tag of a function that reached byte + readable
(auto-clear); a stale tag is warning M2, both tags at once error M2.

## Queues

```
uv run dcp next [--base | --deep | --names] [-n N] [--unit U] [--shard k/N]
```

Over the separated units (L.unit.extent):
- **base**: functions below shape + readable without a level tag; every code draft before any readability-only
  work; units with the fewest drafts first (then the fewest readability items); address order inside a unit.
- **deep**: the `@deep` / `@stuck` functions plus everything below byte + readable in units whose base work is
  done; units by their total distance, smallest first; the closest function first; `@stuck` last. A Q-only
  item (byte, not readable, escalated) waits behind its unit's byte work.
- **names**: the Q-only deep items.

Shards: rendezvous hashing of the unit start (`sha1("<start>:<k>")`), `--shard k/N` or the file `.dcp/shard`.

## Baseline (`ledger/grades.tsv`) and M1

`dcp promote` (main checkout only) writes `target, address, name, unit, code, readability, level, accepted`
for every function of every target (a header line, sorted by target in config order, then address). M1: a
function of the baseline whose grade fell (byte → lower, shape → draft, readable → draft, or no grade any more)
is an error. `dcp check --against REV` compares with the baseline at a git revision.

`dcp promote` raises entries only: when a function fell against the baseline it lists the falls, writes
nothing and exits 1 (`--accept-falls` writes them, each noted `.. at <commit>: promote --accept-falls`). The
narrow way past one fall is `dcp accept ADDR|NAME --to shape|draft [--readability draft] --why TEXT` (main
checkout only): it lowers that one entry to the grade the function has now and fills its `accepted` column,
`byte+readable -> shape+readable at <commit>: <why>`; M1 then holds the function at the accepted grade (a
further fall is an error again). The note stays while the function is below the grade it fell from and is
cleared by the promote that sees it back. Whether a fall is worth accepting is the worker's judgement
(dcp-match-base, 2.6): the change brings the code base as a whole closer to the original and the lost match is
no evidence of the original's source (a VC6 declaration-set tie-break). An older 7-column file reads with
empty notes; the next promote or accept writes the 8-column form.

## The full link (`dcp link`)

LINK.EXE over the target's objects in the order of their least function address, `/OPT:REF /OPT:ICF /MAP`,
`/INCLUDE` of every external function symbol, for a dll `/DLL /BASE:<image base> /DEF:<generated from the
exports with their ordinals>`, the target's archives, the import library of every imported DLL, a generated
entry object when the start-up code calls an entry the sources name otherwise, and an alias object of weak
externals for the several source names of one data address. Output under `build/link/<target>/`; unresolved
externals are classified into `data` (a data name of the sources nothing defines), `renames` (a stale name of
a function whose source defines another), `aliases` (a name at another data object's address), `undrafted`
(a placeholder or registered name of an address the sources do not define yet, and every export without a
source, which the generated .def leaves out: open layout work, milestone 4), `library` (a name no class above
takes that an archive the target does not declare defines: an archive directly in the project's `libs/` or the
toolchain's library directories, `[toolchain] lib_dirs` first; the line names the archives and the `dcp libs
declare` that adds one; the symbol tables come from each archive's first linker member, indexed once per
archive content hash in the store's blob table and read only when such names remain) and `other`; the link is
ok when nothing but `undrafted` is unresolved. A `library` name of the last link also reopens the obligation
`libs.archives` (`dcp status`, the gate), with the archives and the names they define as evidence.
The link is part of `dcp check` once a target has a compiled unit; it is skipped (read back) when no input
changed.

## The toolchain probe (`dcp toolchain probe`)

Every byte-matched function is an anchor; its unit compiles under the flag grid (VC6: `/O1 /O2 /Ox` ×
`/G3 /G4 /G5 /G6 /GB` × `/Oy /Oy-` × `/Gy` × `/GF /Gf` × `/Ob0 /Ob1 /Ob2`; refused combinations pruned). The best
combination matches the most anchors (ties: the declared flags, then the compiler's defaults). A flag is
*distinguished by N anchors* when every other value of its group loses an anchor; else *indistinguishable*
(the report names the values that keep every anchor). `M.flags.proven` makes a flag proven only when its
anchors come from at least two units. CRT sources under the toolchain root (VC98/CRT/SRC) whose objects are
placed library members are compiled too and reported apart: they were built by another compiler build with
the library's flags and prove nothing about the user's units.

## Lint (`dcp lint`)

clang, in process through the LLVM installation's libclang (the core's clang.rs; `[lint] libclang = ...`, else the
libclang.dll beside `clang` on PATH, else `C:/Program Files/LLVM/bin/libclang.dll`), parses each unit's file (the target's define set) as
C89 with MS compatibility against the toolchain's headers: M6 / M7 and Q7. The units one lint parses go to
worker processes; a unit relinted alone (after an edit of it) is parsed in process and kept live, so the next
edit reparses it over its precompiled preamble. M5 comes from an
all-declarations unit (build/lint/<target>/alldecls.c): the system headers the sources include, every
`include/*.h` (a header after the headers that define the names it uses, and after its includer), the
sources' file-scope prototypes and extern data declarations behind `#line` (with the macros of their unit they
use, `GAPDATA`), then the sources' non-static definitions (a function's head as a prototype, a K&R definition
compared as its default-promoted prototype (`f(x) short x;` as `f(int x)`), a data definition as an extern declaration). One M5 line per symbol:

- **against the definition**: every other spelling is renamed and compared with the definition by
  `__builtin_types_compatible_p` on their addresses, so the line lists the definition (file:line, unit,
  spelling) and every declaration that disagrees (grouped by spelling) or agrees, whatever order clang would
  see them in (`unknown`: a declaration that uses a type of its unit). Fixing one disagreement reveals no next one.
- **without a definition in src/** (or with one that uses a type of its unit): clang's pairs, each
  redeclaration against the first declaration seen, still one line per symbol.
- a struct, union, enum or typedef two headers define differently.
- **a header that does not compile there** (with its first error, and the macro of another header it collides
  with): its declarations are not compared, so their conflicts are hidden until it compiles.

A pair whose two sides read the same after whitespace normalisation, or one side of which has an error of its
own, is clang's error recovery and not reported. Only `@original why` / `@vc6 why` on a line exempt a
diagnostic, and for M5 only on a declaration in src/: a header is included into many units and repeats the
definition's spelling, so a unit's own spelling belongs in that unit, as a cast macro in its head region
(`#define name_X ((T (*)(..))name) /* @original why */`); the M5 line of a marked header spelling says so and
names the defining unit and the spelling to repeat. A header the original only included into some units
(zlib's deflate.h / infutil.h each define `struct internal_state`) says so with `@private UNIT[,UNIT..]` in its
first 20 lines: it is left out of the all-declarations unit, and a file outside those units that includes it is
an M5 error. Per-unit results are cached by the unit's text, the clang arguments, libclang's version and the unit's include
hash. `dcp check` lints when libclang is installed.

`dcp headers conflicts UNIT HEADER..` (the core's headers.rs) answers "what would including these headers into
the unit's head collide with" before the include is made: the unit is parsed twice the way lint parses it,
as it is and with the includes after its last one (or before the first file-scope statement using a name
the headers declare, when that comes first: a head that uses a duplicate above its last include; `--at LINE`
chooses the line), and only the trial's new diagnostics count:
`supersedes` (a declaration of the unit the header declares differently), `duplicate` (one it repeats with
the same type: safe to drop; every name of a multi-name `extern a, b, c;` line), `clash` (two headers disagree), `header` (the header does not compile in this
unit's include set), `call` (a call the header's prototype rejects, with the original's pushes and `add esp`
at that function's call of the callee), `vc6` (an error only VC6's own front end reports: both files also go
through `CL /Zs` with the unit's flags, since clang accepts what VC6 rejects, e.g. C2079 for a struct passed by
value that is incomplete in the unit), `prototyped` (calls that compiled without a prototype and now convert
their arguments; per call site `constants: safe` when every argument is a constant whose push cannot change,
else re-grade: an expression, an integer constant to a float parameter), `other`; then the functions to
re-grade and two warnings: `declaration-set` (the includes add declarations or --write drops duplicates: under
VC6 /O2 the declaration set alone moves code generation, so every function of the unit is re-graded, byte ones
first, and they are listed) and `q6` (a duplicate's comment is the only description of a function: dropping it
drops the function to draft under Q6; function addresses only). `--write` inserts the includes and drops the
duplicates (a line whose names are all duplicates goes, a multi-name line keeps its other declarators), only when
nothing else is left and the trial without them has no new error (clang's or VC6's). About 1 s a unit (more
with the VC6 trial).

## The gate (`dcp check`)

Per target: build the stale units, lint (when clang is installed), refresh every rule, fail on any bug or
error conflict (M.compile, M.gen, M1, M5, M6, M8..M10, D1, D4..D6, the setup and layout checks, A1, L13..L15:
docs/layout.md), link (once a unit is compiled) and fail on unresolved externals, then the open toolchain and
libs obligations (after the link: a `library` name reopens libs.archives); `--against REV` adds the grade
comparison.
