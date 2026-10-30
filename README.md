# decompanion

A framework for byte-matching decompilation of VC6-era PE32 x86 binaries (exe and dll), built around a
**per-byte ledger with an evidence ladder**. For every byte of the original it answers: which section, which
symbol (function, thunk, fill, jump table, string, library data, ...), which unit and source, and **how sure
we are**.

The first attempt at this (the GildeGold.exe decomp in `../rea`) is the reference; decompanion is the refined
second iteration. Design and milestones: [docs/plan.md](docs/plan.md). Declarations and address comments:
[docs/layout.md](docs/layout.md). The plugin seams and the conventions the rules rest on:
[docs/architecture.md](docs/architecture.md). Build, compare, grades, queues and the link: [docs/match.md](docs/match.md).

## The model

- **Fact** (`ledger/fact.py`): one statement about an interval `[lo, hi)` of the image: `kind` (section,
  region, symbol, start, name, source, unit, boundary, toolchain, ref, evidence, grade, build), a `value`, a
  `level`, and `by` = the producer (`rule:S.crt.code@1`, `decl:decl/text.dcl:17`, `src:src/net/f_10001000.c:1`).
- **Levels**, combined by `min`: `proven` (forced by bytes) > `derived` (a deterministic rule resting on a
  named toolchain convention) > `declared` (a human, with a reason) > `open` (nothing known). No
  "plausible", no numbers. **Explicit or computed**: every fact is a written rule or a declaration with a
  reason, or it is open.
- **Conflicts** are records, not levels: two facts that contradict each other both stay; `dcp conflicts`
  lists them, `dcp check` fails on errors and bugs (proven vs proven = a rule is wrong).
- **Rules** (`rules/*.py`): `@rule(id, version, ceiling, needs, outputs, inputs)` on a function whose
  docstring is the exact criterion. The engine (`rules/engine.py`) memoises each run by the hash of the
  rule's code (and of the helpers it names), its version, the output of every rule it needs and every
  external input it declares; a rule cannot read what it did not declare. `dcp rules -v` prints the graph
  with every criterion.
- **Loaders** (`L.decl`, `L.src`, `L.analyzer`) are the only rules that turn typed state into facts: they emit
  `declared` facts whose producer is a file line, and refuse a missing reason. Declared facts are re-checked
  by the computed rules on every run, never trusted.
- **Targets** (`decompanion.toml [[target]]`): one project may hold several binaries of one codebase; the
  first is the default, every command takes `--target NAME`. Each target has its own **store**
  (`ledger/store.py`), `build/<target>.sqlite`, holding runs, facts, conflicts, blobs and the materialised
  byte map. A store is a cache: delete it and the next command recomputes. A worktree (`dcp wt new`) overlays
  main's store of the same target. Each target declares its own toolchain (`compiler`, `linker`, `cflags`,
  `archives`, each with `reason.<key>`; `[toolchain]` holds the plugin, the root and defaults a target
  inherits).
- **Obligations** (`obligations.py`): decompanion takes no decision of the decompilation. `dcp init` declares
  nothing; every human decision (the compiler and linker builds, the toolchain root, the flags, the static
  libraries, the analyzer) is an obligation computed from the configuration and the store, named by `dcp
  status` when it is due with the evidence known so far and the command that resolves it. A declaration (`dcp
  toolchain declare`, `dcp libs declare`, `dcp analyzer declare`) needs `--why`, is level declared, and the
  rules raise it. Rules whose input is not declared yet wait (`dcp rules`: `waiting: toolchain.root`).

- **Seams** (docs/architecture.md): the rules (`rules/`, `ledger/`) know no container, object format,
  toolchain, instruction set or analyzer. They ask five plugin kinds, each a package with a registry its
  plugins register into: `image/` (Image: sections, imports, exports, relocations, its own region vocabulary;
  PE32), `objfmt/` (ObjectFormat: archive objects, relocations as absolute / relative / absolute-rva with a
  width and `resolve`; COFF), `toolchains/` (Toolchain: fill forms, import stubs and their placement,
  function alignment, user entry names, Rich vocabulary, installs and their versions, run-time archives;
  VC6), `isa/` (Isa: a decoder of
  compact instruction records with flow kinds, table shapes; x86-32 through capstone) and `analyzers/`
  (Analyzer: a third-party tool's opinions, function starts, names and pseudocode per function, and the
  dialect of that pseudocode; Ghidra headless, saved REA files, none). A target selects `image` and `isa` in
  its table (the ISA defaults to the image's machine type), the project its toolchain and its analyzer
  (`[analyzer] plugin`, default `ghidra`).

## Phases

1. **setup** (`dcp setup`): headers, sections, imports, exports, base relocations, the Rich header (its
   compiler and linker candidates; the target's declaration picks one of each and `C.toolchain` checks the
   pick), library members placed by masked byte search with relocation-site coincidence (`S.crt.code`), the
   names those members' relocations prove (`S.crt.refs`: the user's `DllMain`, CRT data), import thunks
   (`S.thunk`: only where LINK's layout makes `jmp [iat]` an import-library contribution; elsewhere it is a
   compiled tail call), strings, a recursive-descent code walk with tail-call and inner-label handling
   (`rules/walk.py`), fill, and a total byte map (`S.unknown` closes it). Then the configured analyzer's
   export when its key (analyzer, image, script, our starts) changed: Ghidra headless decompiles every
   function, seeded at our starts; its starts become declared facts (`L.analyzer`), its pseudocode the drafts
   of `dcp draft` (`--no-analyzer` skips it, `--analyzer-force` exports again). Setup runs in two stages
   around the toolchain obligation: a rule whose input is not declared yet waits (the library placement
   `S.crt.*`, `S4`, `C.toolchain`, `S2`, `M.compile`, `M.flags.proven`), so the first `dcp setup` runs the
   rest and prints the obligations; `dcp toolchain declare` and `dcp libs declare` end the waits and rerun the
   rules at once (docs/architecture.md, the obligation model).
2. **layout** (`dcp layout ...`): declarations (`decl/*.dcl`, `ledger/decl.py`), address comments in one
   file per function (`ledger/srcscan.py`), the analyzer's drafts (`ledger/drafts.py`), boundary evidence
   (`L.analyze`: literal first users, fill before a start, leaked source paths), unit extents and status
   (`L.unit.extent`), and the checks L1, L3..L10, L13..L16 (`rules/layout.py`). The layout tooling (milestone 4): a
   draft for every function from the analyzer (`dcp setup`, `dcp report`), the reading commands (`dcp disasm`, `dump`, `refs`,
   `layout literals`, `layout starts`, `layout fptrs`), drafting (`dcp unit new|join|rename`, `dcp draft`, `dcp rename`,
   `names.log`), the session protocol (`dcp session start|status|wrap`; the wrap report lists the grade changes
   against the session's base) and the agent skills `dcp-layout` and `dcp-match-base` (8 functions from `dcp
   next` raised to shape + readable or escalated). See [docs/layout.md](docs/layout.md).
3. **match** (`dcp build`, `grade`, `next`, `link`, `check`): one file per unit, `src/<unit>.c`, compiled as it
   stands per target (a target-only function under `#if` on its `DCP_TARGET_<name>`), one CL.EXE per stale unit in a pool (stale = source, flags or
   include-set contents changed: an edited header recompiles only its includers), masked compare with the DLL
   relocation aid (`M.match` [proven], `M.draft`), M8..M10, data placement (`M.data.site` / `.content` /
   `.draft`, D1 D4 D5 D6), two grades per function (code `draft -> shape -> byte`, readability `draft ->
   readable`, rules B1..B3 / Q1..Q7), the level ladder (`@deep` / `@stuck`), the base / deep / names queues
   with rendezvous shards, the baseline `ledger/grades.tsv` (`dcp promote`, M1), the full `/DLL` link, the flag
   probe and clang as the declaration checker. See [docs/match.md](docs/match.md). The match toolbox (try,
   vargen, respell, ...) is milestone 6.

## Use

The workflow: `dcp init` -> `dcp setup` -> follow `dcp status` (declare the toolchain, the libraries, the
analyzer) -> `dcp session start`. decompanion takes none of the decisions: every one is an obligation `dcp
status` names when it is due, with the evidence it has and the command that resolves it; every declaration needs
`--why`.

### Speed: `dcp serve`

`dcp serve` (src/decompanion/daemon.py) runs one resident process per project root; every `dcp` command of the
project then runs in it (client.py forwards the command line, the cwd and the environment, and streams the output
back), so a command pays neither the interpreter start and imports nor the first read of the image, the sources,
the store and the objects. Without a daemon (or with DCP_NO_DAEMON=1) the command runs in its own process: the
same code, the same output. `dcp serve` starts the daemon detached and returns (`--foreground` keeps it in the
terminal; output in build/daemon.log), so the `dcp` script never stays running: on Windows uv could not replace a
running .venv/Scripts/dcp.exe when it reinstalls decompanion. `dcp serve --status` / `--stop`; a changed
decompanion restarts it by itself.

What makes the loop fast, in the daemon and outside it: content hashes of the source files persisted per project
(build/cache/stamps.pickle, trusted only for an unchanged, non-racy stamp; fsmemo.py), one plan per source state,
the compare of each function memoised by its object, address and next start (an edit compares one unit's
functions again), a rule run whose output did not change keeps its facts, `dcp build` lints the units it compiled
before its one refresh. gildegold, a one-line edit of a function (median, warm daemon):

| step | before | now |
|---|---|---|
| `dcp build` (one unit compiled) | 7.5 s | 1.8 .. 2.8 s |
| `dcp diffclass` / `asmdiff` / `grade` / `next` | 2.2 / 2.2 / 6.1 / 2.2 s | 0.2 s each |
| `dcp dump` / `why` / `draft --show` | 1.2 s | 0.2 s |
| `dcp rename` (one unit) | 13 s | 3.6 s |

DCP_TIMING=1 prints where a command's time went (DCP_TIMING=2: per rule), DCP_PROFILE=1 runs it under cProfile
(build/profile/). tools/bench.py replays the loop on a project (edits applied and reverted) and, with --verify,
checks the store against a forced recompute in a fresh process with the persisted hashes and the kept runs off
(DCP_NO_SHORTCUTS=1, DCP_NO_DAEMON=1).

### Quick start: server.dll (outputs trimmed, real numbers)

1. Create the project. Init records the binary only (name, path, sha256, image format, ISA) and the analyzer the
   machine has (unconfirmed):

```
uv sync                                   # in this repo: the venv (Python 3.15, capstone)
uv run dcp init ../guild-server "C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll" --target-name server
  computed: image=pe32 isa=x86; declared: nothing (toolchain, libraries, analyzer: the obligations of dcp status)
  analyzer (to confirm): plugin = "ghidra"  root = "C:/Tools/ghidra_12.1.4_PUBLIC"  java_home = "..."
cd ../guild-server && uv sync             # the target project depends on decompanion by path
git add -A && git commit -m init
```

2. The first setup runs every rule that needs no declaration and the analyzer's export (Ghidra: 27 s), and ends
   with the open obligations. The rules that read an undeclared input wait (`dcp rules -v`: `waiting:
   libs.archives`); their facts are missing until then, so the walk runs through the library code unplaced:

```
uv run dcp setup                          # 29 s cold (the rules 1.6 s, Ghidra 27 s)
waiting=8  rules=C.toolchain,M.compile,M.flags.proven,S.crt.code,S.crt.data,S.crt.refs,S2.rich.members,S4.import.libs  on=toolchain.compiler,toolchain.linker,libs.archives
conflicts: error=8                        # C.overlap in library code the archives will explain

dcp status: server
  phase  setup
  open   7 (6 to do now, 1 waiting)
  gate   blocked by 5 open obligations (dcp session start and dcp check fail)

 1. toolchain.compiler target server
    need  the compiler build that made the user's objects (missing)
    seen  Rich compilers cl 12.00.8047 x125, cl 12.00.9044 x37, cl 12.00.8047 x1 C++; built 2003-10-01;
          CRT strings 3 (__MSVCRT_HEAP_SELECT)
    run   dcp toolchain declare compiler="<one of the Rich compilers>" --why "..."

 2. toolchain.linker   target server
    need  the linker build (missing)
    seen  Rich linkers link 6.00.8447 x1; PE linker version 6.00
    run   dcp toolchain declare linker="<one of the Rich linkers>" --why "..."

 3. toolchain.root     every target
    need  the installation of that toolchain (missing)
    seen  installs found: C:/Tools/MSVC600 (...); C:/Tools/MSVC600-SP5PP (...)
    run   dcp toolchain declare root=DIR --why "..."

 4. toolchain.cflags   target server
    need  the compiler flags (missing)
    seen  the vc6 project wizard's release flags /O2 /Gy; dcp toolchain probe proves flags once functions byte-match
    run   dcp toolchain declare cflags="/F1 /F2 ..." --why "..."

 5. libs.archives      target server
    need  the static libraries linked into the image (missing)
    wait  on toolchain.root: declare that first

 6. analyzer           every target
    need  the analyzer whose pseudocode the drafts start from (computed, not confirmed)
    seen  [analyzer] plugin=ghidra as dcp init found it (found at C:/Tools/ghidra_12.1.4_PUBLIC); drafts=616
    run   dcp analyzer declare ghidra|rea|none [root=DIR] [file=PATH] --why "..."

 7. layout             target server
    need  311 of 311 functions of the game code without a source; units open=0 separated=0
    seen  next=0x10001000 kind=func size=304 unit=- start=immediate analyzed=yes (dcp layout next: the evidence)
    run   dcp session start
    then  dcp layout next
    then  dcp draft --next

next: dcp toolchain declare compiler="<one of the Rich compilers>" --why "..."
```

3. The evidence for the toolchain, in full:

```
uv run dcp toolchain
  installs found=2  (the vc6 plugin's places)
    C:/Tools/MSVC600 (cl 12.00.8804 c2 12.00.9782 link 6.00.8447; makes a Rich linker (8447))
    C:/Tools/MSVC600-SP5PP (cl 12.00.8804 c2 13.00.9044 link 6.00.8447; makes a Rich compiler (9044) and a Rich linker (8447))
  pe_linker=6.00  built=2003-10-01  timestamp=0x3f7a8411
  crt strings=3  ('__MSVCRT_HEAP_SELECT', 'runtime error ', 'Microsoft Visual C++ Runtime Library')
  compiler candidates=3  (derived, rule:S.rich@2)
    cl 12.00.8047 (Utc12_C C x125)  [VC6 pre-release build used for the shipped CRT / SDK libraries]
    cl 12.00.9044 (Utc12_2_C C x37)  [VC6 SP5 and SP5 + Processor Pack (cl 12.00.9044, C2 13.00.9044)]
    cl 12.00.8047 (Utc12_CPP C++ x1)  [VC6 pre-release build used for the shipped CRT / SDK libraries]
  linker candidates=1  (derived, rule:S.rich@2)
    link 6.00.8447 (Linker600 - x1)  [VC6 RTM linker (link 6.00.8447)]
  C.toolchain: waiting: toolchain.compiler, toolchain.linker
```

4. Declare the toolchain (any subset of keys per call; the reason is stored per key). The rules run again at
   once and the next obligation shows:

```
uv run dcp toolchain declare compiler="cl 12.00.9044" linker="link 6.00.8447" root="C:\Tools\MSVC600-SP5PP" cflags="/O2 /Gy" \
    --why "Rich: Utc12_2_C 9044 x37 is the one compiler build the CRT's 8047 objects do not explain, ..."
  root=C:/Tools/MSVC600-SP5PP  available=yes  cl=12.00.8804  c1=12.00.8867  c2=13.00.9044  link=6.00.8447
C.toolchain: ok

dcp status: server
  phase  setup
  open   3
  gate   blocked by 1 open obligation (dcp session start and dcp check fail)

 1. libs.archives      target server
    need  the static libraries linked into the image (missing)
    seen  not placed yet: dcp libs candidates places every run-time archive of the root
    run   dcp libs candidates
    then  dcp libs declare ARCHIVE... --why "..."

next: dcp libs candidates
```

5. The evidence for the libraries: every run-time archive of the root placed on its own (S.crt.code's search,
   cached per image and archive: 1.0 s, then 0.3 s), sorted by placed bytes, with the archives that conflict:

```
uv run dcp libs candidates
target=server  root=C:/Tools/MSVC600-SP5PP  archives=13  cached=0  ms=870
  archive=LIBCMT.LIB  members=637  placed=109  bytes=32851  declared=-
  archive=LIBC.LIB  members=637  placed=75  bytes=23514  declared=-
  archive=LIBCMTD.LIB  members=637  placed=21  bytes=4312  declared=-
  archive=LIBCD.LIB  members=637  placed=19  bytes=3847  declared=-
  archive=MSVCRT.LIB  members=104  placed=6  bytes=495  declared=-
  ...                                     # MSVCRTD 4, the C++ libraries and OLDNAMES 0
  conflict=LIBCMT.LIB,LIBC.LIB  overlaps=6  first=0x10019028
uv run dcp libs declare LIBCMT --why "dcp libs candidates: LIBCMT places 109 members against LIBC's 75 ...; Init starts its thread with _beginthread"
  placed: LIBCMT.LIB=109  (S.crt.code)

dcp status: server
  phase  layout
  open   2
  gate   clear
  ...
```

6. Setup again: the waiting rules have run (CRT placement, CRT refs and data, C.toolchain, S5); the starts of
   ours changed, so the analyzer exports again, afresh (27 s); then warm setup is 0.35 s:

```
uv run dcp setup
functions: 586 (proven 212, derived 374); library members placed: 109 LIBCMT.LIB=109
analyzer=ghidra  drafts=678  export=up-to-date  game_functions=311  with_draft=311  analyzer_only=6  ours_only=0  l9=0
conflicts: warn=8

dcp status: server
  phase  layout
  open   2
  gate   clear

 1. analyzer           every target
    need  the analyzer whose pseudocode the drafts start from (computed, not confirmed)
    ...                 # confirm it: dcp analyzer declare ghidra --why "..."

 2. layout             target server
    need  311 of 311 functions of the game code without a source; units open=0 separated=0
    ...

next: dcp analyzer declare ghidra|rea|none [root=DIR] [file=PATH] --why "..."
git add -A && git commit -m "toolchain and libraries declared"
uv run dcp session start                  # gate: ok (an open toolchain or libs obligation fails it)
```

Reading and checking:

```
uv run dcp status                         # the phase, the gate and the numbered next steps (setup's tail too)
uv run dcp why 0x10008cb0 --refs          # everything known about an address (or: dcp why Init, a function / data name)
uv run dcp map 0x10008c00..0x10008e00     # the byte map of a range
uv run dcp facts 0x10008cb0..0x10008d20 --kind name
uv run dcp conflicts                      # contradictions
uv run dcp check                          # the gate (every target, loaders included, no open toolchain / libs obligation)
uv run dcp rules -v                       # the rule graph with criteria, timings and what waits
uv run dcp toolchain                      # per target: the declarations, installs, Rich candidates, C.toolchain
uv run dcp toolchain declare KEY=VALUE... --why "..."   # compiler= linker= root= cflags= plugin=
uv run dcp libs candidates                # every run-time archive of the root placed on its own
uv run dcp libs declare ARCHIVE... --why "..."          # LIBCMT, LIBCMT.LIB or a path
uv run dcp analyzer declare ghidra|rea|none [root= java_home= file= timeout=] --why "..."
```

Match (docs/match.md):

```
uv run dcp build                          # compile the stale units, grade, print the summary
uv run dcp grade [NAME|UNIT|0xADDR]       # the grades with the failing rules and the distance
uv run dcp next [--deep|--names] [-n N]   # the queues
uv run dcp asmdiff NAME                   # the instruction diff (capstone, both sides)
uv run dcp diffclass NAME                 # the hunk classes
uv run dcp escalate NAME "why"            # @deep why (dcp stuck NAME "why"; --clear)
uv run dcp link                           # the full link, unresolved externals classified
uv run dcp lint                           # libclang: M5 (one line per symbol, against its definition) / M6 / M7, Q7
uv run dcp headers conflicts UNIT H..     # what including headers into a unit's head collides with, clang + VC6 /Zs (--write: includes + duplicates)
uv run dcp toolchain probe                # the flag grid over the byte-matched functions
uv run dcp promote [--accept-falls]       # raise the grade baseline ledger/grades.tsv (main only; refuses a fall)
uv run dcp accept FN --to shape --why ..  # lower one function's baseline entry, the reason next to it (main only)
uv run dcp check [--against REV]          # the gate: build, lint, conflicts, link, grade falls
```

Targets:

```
uv run dcp target list
uv run dcp target add exe "C:/Program Files/GOG Galaxy/Games/The Guild Gold/GildeGold.exe"   # declares nothing
uv run dcp --target exe toolchain declare compiler=... linker=... cflags=... --why "..."     # its own obligations
uv run dcp --target exe setup             # or: uv run dcp setup --target exe
uv run dcp setup --all-targets            # every target in config order (also: dcp report --all-targets)
```

`dcp init` and `dcp target add` declare nothing: the declarations land in the target's table (the compiler,
linker, flags and archives) and in `[toolchain]` (the root), each key with its reason, e.g. the exe linking the
DirectInput library:

```toml
[[target]]
name = "exe"
path = "C:/Program Files/GOG Galaxy/Games/The Guild Gold/GildeGold.exe"
sha256 = "d6f20fda..."
image = "pe32"
isa = "x86"
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2", "/Gy"]
reason.compiler = "Rich: Utc12_2_C 9044 x157 ..."
reason.linker = "..."
reason.cflags = "..."
archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB", "{toolchain.root}/VC98/Lib/DINPUT.LIB"]
reason.archives = "dcp libs candidates: ..."
```

`dcp init` also writes the project's analyzer, the third-party tool `dcp setup` runs for a draft of every
function: Ghidra with the installation it found, else `plugin = "none"` (drafts are then `@rough` skeletons). It
stays the obligation `analyzer` until `dcp analyzer declare ghidra|rea|none [root= file=] --why "..."` confirms
or changes it.
Saved REA `batch_decompile` results instead of a run: `plugin = "rea"`, `file = "..."` (or a list).

```toml
[analyzer]
plugin = "ghidra"                                   # ghidra | rea | none
root = "C:/Tools/ghidra_12.1.4_PUBLIC"              # else $GHIDRA_INSTALL_DIR, else the newest C:/Tools/ghidra_*
java_home = "C:/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot"   # else $JAVA_HOME, else the newest JDK 21
timeout = 60                                        # seconds per function for Ghidra's decompiler
```

Layout:

```
uv run dcp layout next [-n N] [--start ADDR]   # the first function without a source, with its evidence
uv run dcp layout units [-v]                   # the unit table: range, status, boundary levels, open bytes
uv run dcp layout unit propose 0x10008cb0..0x10008d20 --name dllmain --by guess --why "DllMain, Init, Exit"
                                               # runs L3/L4/L7/L8 on the proposal, writes the boundary lines
uv run dcp decl add "0x1000f3a0..0x1000f3b8 bytes dead -- unreachable epilogue copy"
uv run dcp report [-v]                         # with the analyzer line: drafts, starts only it / only we have, L9
uv run dcp draft 0x10008d20 --show             # the analyzer's draft as stored
uv run dcp disasm 0x10008cc0                   # the original with the ledger's names (--ours NAME: our object)
uv run dcp dump 0x10027d08 0x20 --str          # bytes, strings, dwords (--dword), floats (--float)
uv run dcp refs Init                           # everything that names a function or datum
uv run dcp layout starts 0x10008c00..0x10009000     # every start with its evidence
uv run dcp layout literals 0x10008c00..0x10009000   # the literal-pool view (B-LIT): first users, blocks, interleaving
uv run dcp layout fptrs UNIT                        # function pointers in data (tables) with their units
uv run dcp unit new NAME --range 0xA..0xB --by guess --why "..."   # propose + src/NAME.c, include/NAME.h, notes/units/NAME.md
uv run dcp draft --next                        # the next function into its unit's file (the analyzer's pseudocode or a @rough skeleton)
uv run dcp fn NAME|0xADDR                      # one function of the sources: its file, lines and text
uv run dcp unit join A B --why "..."           # B into A (grades must not change)
uv run dcp unit rename OLD NEW --by leaked|tag|guess --why "..."
uv run dcp rename OLD NEW --why "..."          # one identifier (OLD may be [TARGET:]0xADDR); names.log
uv run dcp session start                       # the gate and the overview; starts the session clock
uv run dcp session status                      # the clock: elapsed, left, over
uv run dcp session wrap                        # build, link, check, promote, the computed report
uv run dcp skills install                      # the skills into .claude/skills/ (dcp init installs them)
```

Worktrees:

```
uv run dcp wt new w1                      # ../<project>-wt/w1 on branch wt/w1, store overlaid on main's
uv run dcp wt list
uv run dcp wt drop w1 [--force]
uv run dcp seed ../<project>-wt/w1        # plain copy of the stores (fallback)
```

Output is one record per line, `key=value` tokens, addresses `0x%08x`, intervals `lo..hi` (hi exclusive);
`--json` on `facts`, `conflicts`, `target list`, `layout next`, `layout units`.

## Repository

```
src/decompanion/
  cli.py cli_match.py cli_read.py cli_draft.py cli_layout.py cli_session.py cli_decide.py config.py init.py
  obligations.py tomledit.py         # the guided decisions: obligations, dcp status; declarations into decompanion.toml
  ledger/   fact.py store.py query.py decl.py srcscan.py drafts.py layoutview.py grades.py names.py
  rules/    engine.py setup.py walk.py checks.py layout.py match.py match_data.py grade.py   # generic: the seams only
  build/    amalg.py compile.py link.py probe.py analyzer.py libcand.py   # the tools run here (one process per unit), never in a rule
  data/     ghidra/DcpExport.java dcp_ghidra.h   # the Ghidra post-script, Ghidra's type names (analyzers/ghidra.py)
  match/    compare.py diffclass.py              # masked compare, instruction diff and hunk classes
  repo/     wt.py session.py         # worktrees and seed; the session record and report
  source/   cparse.py lint.py draft.py units.py edit.py   # libclang (the C front end); the files dcp draft / unit / rename write
  image/    __init__ (registry) base.py pe32.py         # Image seam: sections, directories, regions, relocations
  objfmt/   __init__ (registry) base.py coff.py         # ObjectFormat seam: archives, objects, relocation view
  toolchains/ __init__ (registry) base.py vc6/          # Toolchain seam: fill, stubs, entries, Rich, defaults
  isa/      __init__ (registry) base.py x86.py          # Isa seam: instruction records, flow kinds, table shapes
  analyzers/ __init__ (registry) base.py ghidra.py rea.py none.py   # Analyzer seam: starts, names, pseudocode, dialect
tests/                               # a synthetic PE32 dll (conftest.py); server.dll / VC6 / libclang tests when installed; `-m ghidra` adds the 30 s Ghidra export
docs/                                # plan.md, layout.md, match.md, architecture.md
skills/                              # dcp-layout/, dcp-match-base/ SKILL.md (installed into a project's .claude/skills/)
```
