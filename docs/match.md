# Match: build, compare, grades, the full link

The match phase compiles the sources, compares every compiled function with the original's bytes, grades
each function, and links the whole target. The sources stay the typed state: an address comment is a
declared candidate (`L.src`), the match rules verify it and emit facts above the declared level.

## Build (`dcp build`)

```
uv run dcp build [--target T | --all-targets] [--force]
uv run dcp unit cat UNIT          # the amalgamation as the compiler sees it
```

One translation unit per (unit, target): `build/amalg/<target>/<unit>.c` = `src/<unit>/head.c`, the fragments
`f_<addr>.c` in the target's address order, the unlinked fragments `u_<name>.c` in name order, `tail.c`, each
behind `#line 1 "<its path>"` (diagnostics name the fragment). A fragment belongs to the targets its address
comment lists (a bare address: the default target), an unlinked one to every target; a unit without a
fragment of the target is no unit of it.

Flags: the target's `cflags`, then the cflags of the first `[[toolchain.unit]]` whose `glob` matches the unit
name (optionally restricted by `targets = [...]`; a `reason` is mandatory):

```toml
[[toolchain.unit]]
glob = "zlib*"
cflags = ["/Ob1"]
reason = "zlib's own makefile flags"
```

Include directories: `src/<unit>` and `include/`; the toolchain adds its own headers (VC6: `VC98/Include`,
`[toolchain] include_dirs` first) and libraries (`VC98/Lib`, `[toolchain] lib_dirs` first).

A unit is stale iff its source hash (the amalgamation's text), its flags hash or its include hash (the contents
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
| `M.compile` | proven | one `build` fact per unit (ok, object, flags, diagnostics, stale); a failed or never compiled unit is an error, a stale one a warning; `M.gen`: every function of the object has exactly one fragment of the unit and vice versa |
| `M.match` (R1) | proven | the function's section bytes equal the image's at the fragment's address with our relocated fields masked; the original does not continue after our end (only fill up to the next start); for a dll every absolute relocation site of ours is a base-relocation site and the counts agree (`relocs 7/7`). Emits a `symbol` func (to the last non-fill instruction or the first switch table) and a `source` fact (what: match) |
| `M.draft` (R2) | ≤ declared | a compiled function that is no match owns the walk's extent: a `source` fact (what: draft) with why it differs |
| `M8.reloc` | proven | for a match (or aligned relocation sites): M8 our relocation names X registered elsewhere than the original's site holds; M9 string literal bytes differ; M10 float constant bits differ |
| `M.data.site` | proven | a byte-matched function's relocation confirms a data definition's address comment |
| `M.data.content` | proven | the definition's initialised bytes equal the image's at the declared address and occur nowhere else in initialised data |
| `M.data.draft` | declared | every other data definition with an address |
| `D.data` | — | D1 extent overlaps the next symbol, D4 definition order vs address order per unit and section kind, D5 a tentative definition in uninitialised data, D6 a pointer-table entry refers elsewhere than the original's |
| `M.lint` | — | M6 clang error inside a unit, M5 declaration conflict across units, M7 call without a prototype (warn); from `dcp lint` |
| `M.flags.proven` | proven / declared | per flag group of the last probe: proven when anchors from ≥ 2 units distinguish the flag |

## Grades

Two grades per (function, target), computed by `G.grade` (rules/grade.py) into `grade` facts:

**code** `draft → shape → byte`
- B1 byte: M.match holds.
- B2 shape: every differing hunk of the instruction diff is `fill`, `order` (same multiset), or explained by
  the ISA (`regs`, `slots`, `order` after a register renaming, `sib`, `fpu`); or the leftover `code` hunks are
  the same multiset on both sides; or one bijective register / slot renaming explains the whole function.
- B3 draft: otherwise, or no compiled object.

**readability** `draft → readable`: Q1 the name is no placeholder, Q2 no placeholder identifier in the
definition, Q3 no image address literal, Q4 no `*(T *)` cast or macro hiding one, Q5 no ROUGH / SKELETON /
TODO / FIXME / XXX / `@rough`, Q6 the address comment (or another comment) describes the function, Q7 every call
goes through a prototype (only for units the last `dcp lint` parsed; otherwise not evaluated, and `dcp grade`
says so).

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

`dcp promote` (main checkout only) writes `target, address, name, unit, code, readability, level` for every
function of every target. M1: a function of the baseline whose grade fell (byte → lower, shape → draft,
readable → draft, or no grade any more) is an error. `dcp check --against REV` compares with the baseline at a
git revision.

## The full link (`dcp link`)

LINK.EXE over the target's objects in the order of their first fragment's address, `/OPT:REF /OPT:ICF /MAP`,
`/INCLUDE` of every external function symbol, for a dll `/DLL /BASE:<image base> /DEF:<generated from the
exports with their ordinals>`, the target's archives, the import library of every imported DLL, a generated
entry object when the start-up code calls an entry the sources name otherwise, and an alias object of weak
externals for the several source names of one data address. Output under `build/link/<target>/`; unresolved
externals are classified into `data` (a data name of the sources nothing defines), `renames` (a stale name of
a function whose fragment defines another), `aliases` (a name at another data object's address) and `other`.
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

clang (`[lint] clang = ...`, else on PATH, else `C:/Program Files/LLVM/bin/clang.exe`) parses each
amalgamation as C89 with MS compatibility against the toolchain's headers, plus an all-declarations unit that
includes every `include/*.h` and repeats every file-scope prototype of the sources: M6 / M5 / M7 and Q7. Only
`@original why` / `@vc6 why` on the line exempt a diagnostic. Per-unit results are cached by the unit's text,
the flags and its include hash. `dcp check` lints when clang is installed.

## The gate (`dcp check`)

Per target: build the stale units, lint (when clang is installed), refresh every rule, fail on any bug or
error conflict (M.compile, M.gen, M1, M5, M6, M8..M10, D1, D4..D6, the setup and layout checks), link (once a
unit is compiled) and fail on unresolved externals; `--against REV` adds the grade comparison.
