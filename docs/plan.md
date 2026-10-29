# decompanion: a framework for byte-matching decompilation (plan)

Approved 2026-10-29. Milestone status: M1 done 2026-10-29 (`dcp setup` on server.dll, see README); M2..M6 open.

## Context

The GildeGold.exe decomp in `C:\Users\andre\Documents\rea` (package `tools/gildegold`, 3900 commits) is the
first attempt. It proved a set of principles the user wants to keep: the sources are the typed state (address
comment per function / data symbol), "explicit or computed" (every fact is a written deterministic rule or a human
declaration with a reason, else unknown), two grades per function, computed queues, a pre-commit gate, solo
timer sessions run by agent skills, parallel worktrees merged by tooling. It also showed what hurts: the setup
phase was done by hand (notes/binary-facts.md), there is no explicit confidence anywhere, state facts are scattered
over source tags + csv + toml + notes, ~10 ad-hoc JSON caches with their own keys, a header edit recompiles all
92 units, one CL.EXE per flag group (a failed group leaves no stamps → phantom regressions), objdump via tempfiles
per function, and nearly every merge conflict came from project-wide renames in hub files.

The user wants a second, refined iteration: a generic framework **decompanion** (new repo
`C:\Users\andre\Documents\decompanion`, sibling of `rea`, Python ≥ 3.15 with uv) for VC6-era PE32 x86 exes and
dlls, built around a per-byte ledger with an evidence ladder, three framework-steered phases (setup → layout →
match), aggressive content-hash caching, and merge-free-by-construction parallel work. `rea` stays as it is and
serves as the reference to lift code from. First target: `C:\Program Files\GOG Galaxy\Games\The Guild
Gold\server\server.dll` (linker 6.0, 2003-10-01 like GildeGold.exe, Rich header: 37 objects of C2 build 9044 =
VC6 SP5+PP, LIBC 8047 static, .text 0x210a6, `.reloc` present, exports `Init`/`Exit`, imports
KERNEL32/USER32/WS2_32/WINMM). Toolchain at `C:\Tools\MSVC600-SP5PP` (must be re-confirmed by the setup phase with
its own evidence).

Decisions taken with the user (2026-10-29): new repo named decompanion; server.dll first; confidence = enumerated
evidence ladder per fact (no numbers); VC6 PE32 x86 only, behind plugin seams; **one file per function** compiled
through a generated per-unit amalgamation; unit-level / pre-source declarations in **`decl/*.dcl`** files (one fact
per line, sorted by address); function and data addresses stay in the sources.

## 1. Core model

### 1.1 Facts and the ladder (`src/decompanion/ledger/fact.py`)

`Fact(lo, hi, kind, value, level, by, reason)` over VA intervals `[lo, hi)`. Kinds (closed enum): `section`,
`region` (pe headers / import tables / export tables / reloc / rsrc / pad), `symbol` (`skind` ∈ func, thunk, fill,
jumptable, idxtable, fptr, global, string, float, guid, iat, crt.data, unknown.code, unknown.data; the two
`unknown.*` kinds make the map total), `name`, `source` (file, line, unit), `unit`, `boundary`, `toolchain`, `ref`
(call / jmp / reloc / operand, site → target), `grade`, `build`.

Levels, an `IntEnum` so `min()` combines them: **proven** (forced by bytes: image alone, or image + compiled
artifact compared with relocation fields masked) > **derived** (deterministic rule resting on a named toolchain
convention: fill forms, link order, "a call target is a function start") > **declared** (a human said so, reason
mandatory) > **open** (nothing known). No "plausible", no "guess", no numbers: a guess is a declaration with a
reason or it is open. Every rule has a `ceiling`; an emitted fact's level is `min(ceiling, min(premise levels))`.
Rules distinguish *premises* (level propagates) from *candidates* (verified, level does not propagate: a declared
address comment checked by a byte match yields a proven fact).

`by` = `rule:<id>@<version>` | `decl:<file>:<line>` | `src:<file>:<line>`. Author/commit are not stored; `why`
resolves them lazily with `git blame` (cached).

Conflicts are records, not levels: `Conflict(severity, kind, a, b, rule, message)` emitted by check rules
(`C.*`). Severity from levels: proven vs proven = **bug** (a rule is wrong), everything else involving a level
above open = **error**; `open` is replaced, never contradicted. Both facts stay queryable; `dcp conflicts` lists
them; `dcp check` fails on any.

### 1.2 Where typed state lives (target project)

| state | where | level |
|---|---|---|
| binary facts (headers, sections, imports, exports, relocs, rich, strings) | computed every run, cached | proven / derived |
| target identity | `decompanion.toml [target] path, sha256, image="pe32"` | verified, mismatch fatal |
| toolchain + flags (+ per-unit overrides) | `decompanion.toml [toolchain] ... reason=` | declared → proven per unit by `M.flags.proven` |
| library identification (CRT, SDK) | computed from `.lib` archives in `[libs]` into the signature store | proven |
| function address + description, `@deep` / `@stuck` / `@rough` | `/* 0x10001000, what */` first line of `src/<unit>/f_<addr>.c` (file name must agree) | src: declared → proven when matched |
| data address | `T x = v; /* 0x1002xxxx */` after definition / extern (kept from rea) | src: declared → proven via site / content |
| per-line exemptions `@original why`, `@vc6 why` | in sources | declared |
| unit boundary + name origin, dead bytes, jump tables, foreign blobs, names for addresses without source | `decl/text.dcl`, `decl/data.dcl` | declared |
| rename events (functions, data, **fields, types, macros**) | `names.log`, append-only, `merge=union` | — |
| claims | `claims.log`, append-only, `merge=union` | — |
| grade baseline | `ledger/grades.tsv`, written only by `dcp promote` on main, `merge=ours` | — |
| derived state | `build/dcp.sqlite` + `build/obj/` (git-ignored) | — |

`.dcl` grammar: `ADDR[..END] KIND [k=v ...] -- reason`, closed vocabulary (`boundary start|end tu=`, `bytes
dead`, `jumptable fn=`, `foreign kind=`, `name`, `fptr`, ...), file kept sorted by address (`dcp decl add` inserts
in place; unsorted / duplicate key / missing reason = gate error). Sorted-by-address is what keeps parallel
branches in different hunks.

Source layout per unit: `src/<unit>/head.c` (includes, local types, prototypes, leading file-scope data),
`src/<unit>/f_<addr>.c` (the function plus the file-scope definitions that precede it in TU order, so static data
order and literal pooling follow address order naturally), `include/<unit>.h` (public prototypes with address
comments). `dcp build` writes `build/amalg/<unit>.c` = head + fragments in address order, each behind
`#line 1 "<fragment path>"` (a fragment may carry its own `#line N "<leaked original path>"` to reproduce
`__FILE__` literals). `dcp unit cat UNIT` prints the same for reading; `dcp unit fold` can convert a finished
project to one file per unit at the end.

### 1.3 Store and caching (`ledger/store.py`)

One SQLite file `build/dcp.sqlite` (WAL). Tables: `input(key, hash)`, `run(rule, version, code_hash,
input_hash, current, ms)`, `fact(run_id, lo, hi, kind, value, level, by, reason)` indexed `(kind, lo)`,
`conflict`, `bytemap(lo, hi, cls, symbol_id, unit_id, source_id, level)` (materialised, non-overlapping),
`blob(hash, kind, data)` (disassembly lists, include sets, CL logs, lib sections), `tu(path, src_hash, flags_hash,
include_hash, obj_hash, ok, log)`, `include_set`, `libsig`, `blame`. Objects stay on disk as
`build/obj/<sha256>.obj` (CL / LINK need files).

Invalidation: every rule run is keyed by `sha256(code_hash ‖ version ‖ hashes of its declared inputs)`; inputs are
files by content hash (never mtime) and fact kinds by hash of their canonical serialisation. Engine start: hash
inputs (~20 ms for 100 files), walk the rule DAG topologically, skip hits, rerun misses, swap facts atomically per
run. A failed rule leaves a `build ok=false` fact, never a missing stamp.

Header-edit trap: `tu.include_hash` hashes only the headers in the TU's **actual** include set, obtained once per
`(src_hash, flags_hash, include-dir listing hash)` from `CL /P` `#line` directives (VC6 has no `/showIncludes`).
Compile: one `CL.EXE` process per stale TU in a `ThreadPoolExecutor(cpu_count)`; the same pool serves try / vargen
/ respell, and a variant whose amalgamation hash is already in `tu` never compiles again. Disassembly: capstone
in-process, memoised in `blob` by `sha256(bytes ‖ mask ‖ va)`; no objdump, no tempfiles.

Worktrees: `dcp wt new` records main's store path; the worktree `ATTACH`es main's `dcp.sqlite` read-only and
`build/obj` by path, writes its own overlay, lookups go overlay-then-main. `dcp seed PATH` (plain copy) stays as
the fallback. `why` is one `bytemap` lookup + per-kind `(kind, lo)` lookups: Python start-up dominates.

### 1.4 Rule engine (`rules/engine.py`)

```python
@rule(id="S.crt.code", version="1", ceiling=Level.proven,
      inputs=("image", "libsig", "facts:section", "facts:ref.reloc"), outputs=("symbol", "name", "unit", "ref"))
def crt_code(ctx) -> Iterable[Fact | Conflict]:
    """<the exact criterion>. Premises: ... Convention: none."""
```

Structural enforcement of explicit-or-computed: a `Fact` cannot exist without `by`; the engine stamps rule
producers; only the two loaders (`ledger/decl.py`, `ledger/srcscan.py`) emit `decl:` / `src:` and refuse a missing
reason; `ctx.facts(kind)` raises for an undeclared input (so the input hash is complete by construction); a yield
above the ceiling or above the premises' minimum raises; `code_hash = sha256(inspect.getsource(fn))` is part of
the run key; the DAG is cycle-checked at import; `dcp rules` prints it with run status and timings.

## 2. Rules by phase

**Setup `S.*`** (`dcp setup`): `S.image` (bytes, base, sha256 vs declared), `S.headers`, `S.sections` (+ `pad`
for raw/virtual slack), `S.datadirs`, `S.imports` (iat slots + `KERNEL32!X` names), `S.exports` (func starts +
names, extent open), `S.entry`, `S.relocs` (one `ref reloc` per base relocation: the DLL's exact list of absolute
operands), `S.rich` [derived] (decode with a shipped prodid table `toolchains/vc6/rich.py`: RH1 largest non-library
count = user compiler; RH2 language C when no `*_CPP` count besides the CRT; RH3 other builds = library members),
`S.libsig` (archives → `libsig`), `S.crt.code` [proven] (member code section placed where its masked bytes equal
the image's, every DIR32 site is a base-relocation site, no base relocation in an unmasked byte, unique hit;
multiple hits = listed ambiguous, nothing emitted), `S.crt.data` (through placed members' DIR32 sites),
`S.crt.flavour` (LIBC vs LIBCMT by member identity), `S.thunk` (`FF 25 <iat>`), `S.strings` [derived] (runs whose
start is a reloc target; unreferenced runs stay candidates), `S.jumptable` / `S.idxtable` [derived], `S.codewalk`
[derived] (recursive descent from every proven/derived start, capstone, never into a known symbol; emits func
extents + call/jmp refs), `S.fptr` [derived] (reloc whose target is in `.text` and not a table entry),
`S.fill` [derived] (VC6 fill set 90 / CC / 8B FF / 8D 49 00 from the toolchain plugin), `S.entry.dllmain`
(the non-library call target of `_DllMainCRTStartup`), `S.pubsrc` (catalogue version strings → public-source
candidates; compiled candidates scanned like lib members), `S.probe` (`dcp toolchain probe`: compile anchors —
CRT sources if present, public-source hits, later every matched function — under the flag grid `/O1 /O2 /Ox ×
/G3..G6 × /Oy /Oy- × /Gy × /GF /Gf × /Ob0 /Ob1`; each flag reports *distinguished by N anchors* or
*indistinguishable*; the toolchain fact becomes proven only for flags distinguished by ≥ 2 units), `S.unknown`
[open] catch-all, `B.bytemap`. Checks: `C.overlap`, `C.ref.target` (call into the middle of a proven function),
`C.reloc.unmasked` [bug], `C.toolchain` (declaration vs Rich), `S1` sizes vs file, `S2` Rich counts vs members
found, `S4` import DLL without import lib, `S5` unexplained gap in the CRT region, `S7` export/entry outside
`.text`, `S8` public-source string without a compiled match.

`dcp toolchain` prints the evidence view: rich / libs (members matched) / probed (anchors, units, flags
distinguished) and which flags are still declared only.

**Layout `L.*`** (`dcp layout ...`): loaders `L.decl`, `L.src`; `L.analyze` once per image hash: starts with
their evidence (export / entry / call / immediate / reloc-pointer / ghidra-declared), call graph, fill runs,
**literal-pool order** (per function the sorted data targets of its reloc sites, per literal its first user; exact
for a DLL), string xrefs, Ghidra bulk export (`dcp ghidra import JSON` from REA `batch_decompile` first; headless
`analyzeHeadless` script later) stored as blobs by (image hash, start). Boundary evidence rules: `B-LEAK` leaked
path referenced by the function [proven], `B-LIT` first-user order monotone within a unit [derived], `B-FILL`
boundary at a start after fill or `ret` [derived; `nop` runs prove nothing], `B-REG` registration tables
[derived], `B-CPL` codegen coupling [declared by the match worker with evidence], `B-DECL` subsystem guess with
reason [declared]. `L.unit.extent` (R7: first function to the next unit's first; lib units end the game code, so
`game_range.toml` disappears), `L.unit.order` (D7/D8). Checks `L1` draft walk crosses another start, `L2` proven
start inside a unit without a fragment, `L3` B-LIT contradiction, `L4` boundary not at a start / inside fill,
`L5` placeholder name whose address is not a start, `L6` declared fact whose rule now fails (declared facts are
re-checked every run, never trusted), `L7` extent overlap, `L8` two leaked paths in one unit, `L9` Ghidra function
spanning a proven start, `L10` walked code reached from nowhere between drafts, `L11` address comment vs file name.
Commands: `dcp layout next` (first open byte with start evidence, callers, literals reached first, size to the next
start, Ghidra draft availability), `dcp layout unit propose 0xA..0xB --name N --why ...` (runs L3/L4/L7/L8 before
writing the decl line), `dcp layout units`.

**Match `M.*` / data / grades `G.*`**: `M.includes`, `M.compile` (`build` facts), `M.match` [proven] (R1 + DLL
aid: every DIR32 of the COMDAT section is a base-relocation site and the reloc count inside the extent equals the
object's, shown as `relocs 7/7`), `M.draft` [derived] (R2 via the walk), `M.bytes.declared` (R5), `M.flags.proven`,
`M.data.site` / `.content` / `.iat` / `.lib` [proven], `M.data.draft` [declared], `M.data.fill` [derived]. Grades:
**code** `draft → shape → byte` (B1..B3 lifted; "shape" replaces "behaviour" because a diff explained by
regs/slots/order classes proves the same shape, not behaviour — behaviour by instrumentation is a separate
declared fact `dcp declare behaviour`), **readability** `draft → readable` (Q1..Q7 lifted; `@rough` tag replaces
the ROUGH/SKELETON words), unit **data** `draft → placed → byte`. Level ladder `base → deep → stuck` via
`@deep why` / `@stuck why` in the address comment (`dcp escalate`, `dcp stuck`, auto-clear at byte+readable;
`escalate` refuses a reason that is only missing statements: reconstruction is base work). Queues `dcp next
--base|--deep|--names|--data` with the rea ordering rules; no skipping; rendezvous sharding by unit start kept.
Checks `M1` grade fell vs baseline, `M2` stale level tag, `M3` stuck without open.md entry, `M4` distance WORSE
without `dcp accept`, `M5`/`M6` clang cross-TU / in-TU conflicts, `M7` K&R call, `M8` reloc-site contradiction
(our object references X where the original's site holds Y — exact for every function of a DLL), `M9`/`M10`
literal text / float bits differ, `M11` byte match depending on foreign code above it, `M12` header-only commit
moved distances in untouched units, `D1..D6` data layout (overlap, alias width, blob touch, head.c order vs
address order, `.bss` needs `= 0`, pointer-table targets vs original relocs), `N1..N4` names (source vs registry,
duplicates, collision, rename touched an `@original`/`@alias` line), `G1..G3` merge (foreign-unit edit, generated
file committed in a worktree, merged byte functions no longer byte on main).

## 3. CLI (`dcp`, argparse, every command refreshes the engine first)

Output contract for agent readers: one record per line, `key=value` tokens, addresses `0x%08x`, intervals
`lo..hi` (hi exclusive), sorted by address then kind, counts before lists, `--json` everywhere.

`dcp init [--from-setup]` · `dcp setup [pe|dirs|rich|strings|sigs build|sigs scan|entry|probe|report]` ·
`dcp toolchain` · `dcp why ADDR` · `dcp facts LO..HI [--kind]` · `dcp conflicts` · `dcp rules` · `dcp check
[--strict] [--against REV]` (the gate: loaders parse, no conflicts, every TU compiles, link resolves, no grade fall,
decl files sorted, UTF-8/LF) · `dcp decl add "LINE"` · `dcp layout next|units|unit propose|analyze` · `dcp
ghidra import` · `dcp build` · `dcp link` · `dcp unit cat|fold` · `dcp grade [NAME|UNIT]` · `dcp next` · `dcp
escalate|stuck|accept` · `dcp promote` · `dcp rename OLD NEW --why` (the only way to rename: edits sources,
appends to `names.log`) · `dcp claim` · match toolbox `dcp asmdiff|diffclass|spell|idioms|siblings|slotmap|
listing|try|vargen|respell|tuorder|c2prio|dump|refs|data next|data table` · `dcp wt new|list|drop|seed` · `dcp
merge BRANCH...` · `dcp session prepare|wrap|report|close` · `dcp lint`.

## 4. Parallelism and merge

- **Files**: one function per file → workers on different functions never touch the same file; `head.c`,
  headers and `.dcl` files are the only shared ones and change additively (sorted inserts).
- **Names**: `names.log` lines `ts addr|TYPE.field|name kind old -> new by:<wt> why:<text>`; `merge=union`;
  fold at merge: latest wins (R-N1), tie → shard owner (R-N2), else `--pick ADDR=NAME`; the loser's name is
  appended as a further event. Lines tagged `@original` / `@alias` are never rewritten (N4). N1 cross-checks the
  log against the sources (name of the definition at the address at branch tip vs merge base, cheap because the
  file name carries the address).
- **Ownership**: rendezvous shards (kept) + explicit `claims.log`; G1 flags foreign-unit edits that are not
  additive.
- **`dcp merge`** (on main, idempotent, resumable): gates → registry fold → each branch back to its base names
  (technical commit, lifted from `session.py`) → `git merge --no-ff` in order layout, branches without
  declaration-surface changes, base-k, deep-k; auto-resolved: logs (union), generated + baseline (ours), fragment
  files (distinct files), head.c / headers / .dcl via the lifted statement-level token merger (M1/M2 rules);
  leftover = a true two-sided edit of one declaration or one function: stop with the file list and each side's
  distance to the bytes → forward rename pass on main → build, link, `check --gate`, `check --against BRANCH`
  (G3), promote, one commit, report.
- **Worktrees** never promote, never merge, never touch `ledger/grades.tsv` (G2 + pre-commit hook).

## 5. Agent integration

`dcp init` installs `decompanion/skills/{dcp-layout,dcp-match-base,dcp-match-deep,dcp-data,dcp-session}/SKILL.md`
into the target's `.claude/skills/` (target-independent text; facts come from `dcp` output). Session protocol
kept from rea: `dcp session start` prints gate + shard + first queue item; own background `sleep 1800` timer; loop
on `dcp next`; one commit per raise / escalate / draft batch (`<unit>: <verb> 0x.. (<skill>)`); `dcp session wrap`
builds, links, checks, prints the computed report. `dcp session prepare B D [--layout]` = gates + `wt new` per
worker + shards + prompts in `build/session/prompts/<w>.md`; the orchestrator launches all workers in one message
and only merges. `dcp session report` is computed from git + ledger + `names.log` (no hand-written session logs;
`src/<unit>/open.md` is the only prose state).

## 6. Repository layout

```
decompanion/
  pyproject.toml              # name decompanion, requires-python >=3.15, deps capstone==5.0.9 (frida optional extra for c2prio);
                              # scripts: dcp = decompanion.cli:main; src layout; tools/sitecustomize-equivalent LF enforcement
  .python-version .gitattributes .editorconfig (LF + UTF-8 everywhere, lifted from rea)
  src/decompanion/
    cli.py  config.py  fmt.py
    ledger/   fact.py store.py decl.py srcscan.py query.py grades.py
    rules/    engine.py setup.py setup_libs.py layout.py match.py match_data.py grade.py checks.py
    image/    base.py pe32.py                 # ImageFormat ABC (sections, dirs, imports, exports, relocs, rich, read)
    objfmt/   base.py coff.py                 # ObjectFormat ABC (.obj, .lib archives)  ← port of link.py Obj/archive_members
    toolchains/ base.py vc6/{__init__,cl,rich,fill,link}.py   # Toolchain ABC: compile, includes (CL /P), link, fill_forms, rich_table
    build/    compile.py amalg.py link.py
    disasm.py                                 # capstone + blob memo
    match/    asmdiff.py diffclass.py spell.py idioms.py respell.py vargen.py tryvar.py siblings.py slotmap.py listing.py tuorder.py c2prio.py
    source/   rename.py refs.py enc.py lint.py declcheck.py
    repo/     wt.py merge.py session.py claims.py
    data/     vc6_rich.toml vc6_idioms.toml pubsrc_catalogue.toml
  skills/     dcp-layout/ dcp-match-base/ dcp-match-deep/ dcp-data/ dcp-session/   (SKILL.md each)
  tests/      synthetic tiny PE + fixtures; server.dll tests skipped when absent
  README.md   (the model, the ladder, the phases, the CLI)

guild-server/   (target project, created by `dcp init`; sibling of rea)
  decompanion.toml  decl/{text,data}.dcl  names.log  claims.log  ledger/grades.tsv  libs/  include/  src/<unit>/{head.c,f_<addr>.c,open.md}
  build/ (ignored)  .claude/skills/ (installed)  pyproject.toml (depends on ../decompanion by path)
```

## 7. Milestones (implementation order)

| # | deliverable | verification |
|---|---|---|
| M1 setup byte map | fact/store/engine, pe32, coff, vc6 rich/fill, disasm, all `S.*` + `B.bytemap` + setup checks, `dcp init`, `dcp setup`, `dcp why`, `dcp facts`, `dcp conflicts`, `dcp rules`, `dcp toolchain` | on server.dll: every byte has exactly one `symbol`/`region` fact; LIBC members placed proven with `.reloc` coincidence; report shows 37 user objects C, static LIBC, CRT region with gaps listed, exports + DllMain starts, toolchain = declared flags; `dcp why` < 100 ms; rerun runs zero rules; unit tests on a synthetic PE |
| M2 declarations + layout | `decl.py`, `srcscan.py`, `L.*`, boundary rules, Ghidra import, `dcp layout *`, `dcp decl add`, `dcp check` (loader + conflict gate), `dcp wt new/seed` (overlay store) | first unit declared on server.dll from `Init` outward; a deliberately wrong boundary and a walk crossing a start are caught (L1/L3/L4) |
| M3 build + compare + grades | `toolchains/vc6/cl.py` (`/P` include sets), pool compile, amalgamation, `M.match` with reloc aid, `M.draft`, `M.data.*`, capstone asmdiff/diffclass, `G.*`, `ledger/grades.tsv`, `dcp build/link/grade/next/promote`, full `/DLL` link with generated `.def`, lint, checks M1..M12, D1..D6 | first functions byte-match; `dcp toolchain probe` promotes `/O2 /Gy` to proven; a header edit that flips codegen is reported by M12; a header edit recompiles only its includers |
| M4 match toolbox | try/vargen/respell on fragments with the shared pool and hash cache, listing, slotmap, siblings, spell/idioms catalogue, tuorder, c2prio plugin, `dcp escalate/stuck/accept`, `dcp data *` | a respell round on a shape-grade function runs with cache hits for repeated variants; deep queue reproducible |
| M5 parallel sessions | `names.log` + `dcp rename`, claims, `dcp merge`, `dcp session *`, skills, pre-commit hook | two worktrees rename one address differently and edit neighbouring functions; `dcp merge` resolves without hand conflicts; G3 passes; a full /dcp-session round on server.dll |
| M6 second target | GildeGold.exe as a second project (exe without `.reloc`, `.data` ordered literal scan replaces reloc evidence) — validates the exe path; no migration of `rea` | setup report rediscovers notes/binary-facts.md (zlib range, CRT start 0x5de4a0, VC6 SP5+PP /O2) |

## 8. What is lifted from `rea` (paths under `C:\Users\andre\Documents\rea\tools\gildegold\`)

Lift and adapt: `link/link.py` (COFF/PE/archive readers, CRT placement idea, full link), `inspect/coverage.py`
(walker), `ledger/ledger.py` + `ledger_data.py` (R1..R7, D1..D8 as rules), `ledger/evidence.py`,
`ledger/grade.py` (B/Q rules, queues, shards), `core/gen.py` (address-comment parser → `srcscan.py`),
`match/*` (diffclass, spell, idioms, respell, vargen, try_variants, siblings, slotmap, listing, tuorder, c2prio),
`decomp/{dump,refs,declcheck,enc}.py`, `decl/lint.py`, `repo/session.py` (back-to-base, token merger, computed
report), `decomp/rename.py` (rules; registry-driven now). Rewrite: `core/build.py` (amalgamation, pool, store),
`disasm.py`/`asmdiff.py` (capstone), `inspect/scan.py` → `dcp sigs`, `inspect/tustrings.py` → reloc-exact literal
order, `repo/seed.py` → overlay. Drop: `game/*` (GildeGold-specific; `dbg` can return as `dcp run` later).

## 9. Rejected designs of the first attempt (one line each)

`@boundary plausible` / `@named_by guess` (a guess is a declaration with a reason or open); unit tags in C headers
(unit facts exist before files do; `decl/` instead); `state_baseline/` csv copies and `config/symbols/*.csv`
(computed or `decl/`); `game_range.toml` (computed from lib units); one CL per flag group (poisoned stamps);
global headers digest (include-set hash); objdump via tempfiles (capstone blobs); ten JSON caches (one store);
regex-based CRT placement at link time (signature store at setup); renames computed by csv archaeology
(`names.log` + N1 cross-check); "behaviour" grade name (overclaims: "shape").

## 10. First implementation step (after approval)

Create `C:\Users\andre\Documents\decompanion` (git init, uv init with Python 3.15, LF/UTF-8 config), implement M1
in this order: `fact.py` → `store.py` → `engine.py` (+ tests on toy rules) → `image/pe32.py` (server.dll +
GildeGold.exe fixtures) → `objfmt/coff.py` (LIBC.LIB) → `toolchains/vc6/{rich,fill}.py` → `disasm.py` → `S.*`
rules → `B.bytemap` → checks → CLI → `dcp init` producing `../guild-server`. Verify with `dcp setup` on
server.dll as in the M1 row, then `dcp why 0x10001000`, `dcp why <Init>`, `dcp conflicts`, and a rerun showing
zero rule runs.
