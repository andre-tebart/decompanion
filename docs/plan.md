# decompanion: a framework for byte-matching decompilation (plan)

Approved 2026-10-29, amended the same day (several targets per project, section 1.5). Milestone status: M1 done 2026-10-29 (`dcp setup` on server.dll, see README); M2 done 2026-10-29 (targets,
declarations, source scan, layout rules and commands, Ghidra import, worktree overlay; see README and
docs/layout.md); multi-target round done 2026-10-29 (per-target toolchain declaration and archives, every command
and loader per target, `dcp setup --all-targets`; server.dll and GildeGold.exe pass `dcp check` as two targets
of one project; S.codewalk on the exe ~35 s -> ~5 s); cleanup round done 2026-10-29 (every VC6 / LINK, PE32, COFF and
x86 / capstone fact moved behind the plugin seams, the instruction-set seam `isa/` added, plugin registries,
`dcp init --toolchain-root` required; facts byte-identical; see docs/architecture.md); M3 done 2026-10-29 (amalgamation per unit and target, pool compile with include-set staleness, M.match with the DLL aid, M.draft, M8..M10, M.data.site / .content / .draft, D1 D4 D5 D6, grades code draft/shape/byte and readability Q1..Q7, queues, ledger/grades.tsv + M1, the full /DLL link, `dcp toolchain probe`, clang lint M5..M7; DllMain, Init and Exit of server.dll byte-match; see docs/match.md); reprioritised 2026-10-29 (user decision: the layout tooling first, section 7: M4 layout tooling, M5 the layout experiment on server.dll, then the match toolbox, parallel sessions and the second target as M6..M8); M4 done 2026-10-29 (the layout tooling: Ghidra
headless drafts for every function, the reading, drafting and session commands, L9 / L10 / R5, the skill
`dcp-layout`; see docs/layout.md and section 12); amended 2026-10-29 (the analyzer seam `analyzers/`: Ghidra, REA
files or none, run inside `dcp setup`; section 12); M5 (the layout experiment on server.dll, by the user) next.

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
through a generated per-unit amalgamation (superseded 2026-10-30 by **one file per unit**, section 19); unit-level /
pre-source declarations in **`decl/*.dcl`** files (one fact per line, sorted by address); function and data
addresses stay in the sources.

Amendment (2026-10-29, after M1): **one project may hold several binaries of one codebase** ("targets": for
The Guild Gold the server dll, GildeGold.exe and GildeGold_TL.exe were built from one tree on one day). The
target dimension is modelled from M2 on (section 1.5) and every setup and layout command runs per target and
across targets since the multi-target round (2026-10-29); M8 adds the one rule that makes sharing pay: same code across targets transfers names and
sources at the proven level.

Reprioritisation (2026-10-29, user decision: "all the tooling that is relevant for layout work first"): before the
match toolbox, every tool a layout session needs (M4), then a layout experiment on server.dll by the user with the
skill (M5); the old M4..M6 follow as M6..M8.

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
| target identity | `decompanion.toml [[target]] name, path, sha256, image="pe32", isa="x86"` (the first is the default target; isa defaults to the image's machine type) | verified, mismatch fatal |
| toolchain + flags (+ per-unit overrides) | per target: `[[target]] compiler= linker= cflags= reason=` (picked from the Rich candidates; `[toolchain]` holds `plugin`, `root` and defaults a target inherits) | declared (checked against the Rich candidates by `C.toolchain`) → proven per unit by `M.flags.proven` |
| library identification (CRT, SDK) | computed from the `.lib` archives of the target (`[[target]] archives=`, else `[libs] archives`) into the signature store | proven |
| function address + description, `@deep` / `@stuck` / `@rough` | `/* 0x10001000, what */` first line of `src/<unit>/f_<addr>.c` (file name must agree); several targets: `/* server:0x10001000, exe:0x4a3000, what */`, a bare address means the default target | src: declared → proven when matched |
| data address | `T x = v; /* 0x1002xxxx */` after definition / extern (kept from rea); same target prefixes | src: declared → proven via site / content |
| per-line exemptions `@original why`, `@vc6 why` | in sources | declared |
| unit boundary + name origin, dead bytes, jump tables, foreign blobs, names for addresses without source | `decl/text.dcl`, `decl/data.dcl` | declared |
| rename events (functions, data, **fields, types, macros**) | `names.log`, append-only, `merge=union` | — |
| claims | `claims.log`, append-only, `merge=union` | — |
| grade baseline | `ledger/grades.tsv`, written only by `dcp promote` on main, `merge=ours` | — |
| derived state | `build/<target>.sqlite` per target + `build/obj/` (git-ignored) | — |

`.dcl` grammar: `ADDR[..END] KIND [k=v ...] -- reason`, closed vocabulary (`boundary start|end tu=`, `bytes
dead`, `jumptable fn=`, `foreign kind=`, `name`, `fptr`, ...), file kept sorted by address (`dcp decl add` inserts
in place; unsorted / duplicate key / missing reason = gate error). Sorted-by-address is what keeps parallel
branches in different hunks.

Source layout per unit (until section 19, which replaces it by `src/<unit>.c`): `src/<unit>/head.c` (includes, local types, prototypes, leading file-scope data),
`src/<unit>/f_<addr>.c` (the function plus the file-scope definitions that precede it in TU order, so static data
order and literal pooling follow address order naturally), `include/<unit>.h` (public prototypes with address
comments). `dcp build` writes `build/amalg/<unit>.c` = head + fragments in address order, each behind
`#line 1 "<fragment path>"` (a fragment may carry its own `#line N "<leaked original path>"` to reproduce
`__FILE__` literals). `dcp unit cat UNIT` prints the same for reading; `dcp unit fold` can convert a finished
project to one file per unit at the end.

### 1.3 Store and caching (`ledger/store.py`)

One SQLite file per target, `build/<target>.sqlite` (WAL; section 1.5). Tables: `input(key, hash)`, `run(rule, version, code_hash,
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

### 1.5 Several targets per project

A project is one codebase; it may hold several binaries built from it. Each is a **target** with a name
(`[[target]]` in `decompanion.toml`, the first is the default). What this costs, all of it in M2:
- Facts stay intervals of one address space: every target has its own store `build/<target>.sqlite`, the
  same schema, the same rules. A cross-target rule opens two stores.
- The address comment grammar takes an optional target prefix (section 1.2): a function compiled into two
  targets lists both addresses; a unit compiled into two targets gets two amalgamations and two grades per
  function (one per target), and `ledger/grades.tsv` carries a target column.
- The `.dcl` grammar takes the same prefix (`server:0x10001000 boundary ...`); a bare address is the default
  target.
- Every `dcp` command takes `--target NAME` (default: the first target). `dcp init` creates one target; `dcp
  target add NAME PATH` adds another. `dcp setup|report --all-targets` and `dcp check` / `dcp toolchain`
  without `--target` run every target.
- The toolchain is declared per target (`[[target]] compiler= linker= cflags= reason=`; `[toolchain]` keeps the
  plugin, its root and defaults a target inherits): binaries of one tree may differ in what built or linked
  them, and the Rich header of each is its own evidence. `dcp init` / `dcp target add` pre-fill the
  declaration from the Rich candidates and say how in the reason; `C.toolchain` checks it per target.
- Library archives are per target too (`[[target]] archives=` replaces `[libs] archives`): the exe links
  DirectX and Miles libraries the dll does not.
- The loaders read every target's lines and keep the current target's: a fragment `/* server:0x10001000,
  exe:0x4a3000, what */` is a fact in both stores, a bare address only in the default target's; a prefixed
  `.dcl` line only in its target's. Errors of the text itself are reported once (the default target's store),
  errors about an address in its target's store.
What this buys, in M8: rule `X.same.code` [proven]: a function of target A whose masked bytes equal a function
of target B (with the relocation fields of both masked, and the dll's `.reloc` evidence attached to the exe's
copy) is the same source compiled with the same flags: names, descriptions, drafted source, unit membership
and the dll's exact data references carry over. Unit order found in one target constrains the other (link
order is the same tree). What stays out until the match phase is working on one target: units that differ
between targets by a define, differing link orders, a function matched in one target but not the other.

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
operands), `S.rich` [derived] (decode with a shipped prodid table `toolchains/vc6/rich.py`; emits every entry and
the candidates — every compiler entry with build, language, object count and the number of configured archive
objects whose `@comp.id` names it, every linker entry — and picks nothing: the pick is the target's declaration),
`S.libsig` (archives → `libsig`), `S.crt.code` [proven] (member code section placed where its masked bytes equal
the image's, every DIR32 site is a base-relocation site, no base relocation in an unmasked byte, unique hit;
multiple hits = listed ambiguous, nothing emitted), `S.crt.data` (through placed members' DIR32 sites),
`S.crt.flavour` (LIBC vs LIBCMT by member identity), `S.thunk` [derived] (`FF 25 <iat>` where LINK's layout
makes it an import-library contribution: after the first placed library section, or adjoining another such jump;
elsewhere the same bytes are VC6's tail call of a dllimport function and the walk reaches them), `S.strings` [derived] (runs whose
start is a reloc target; unreferenced runs stay candidates), `S.jumptable` / `S.idxtable` [derived], `S.codewalk`
[derived] (recursive descent from every proven/derived start, capstone, never into a known symbol; emits func
extents + call/jmp refs), `S.fptr` [derived] (reloc whose target is in `.text` and not a table entry),
`S.fill` [derived] (VC6 fill set 90 / CC / 8B FF / 8D 49 00 from the toolchain plugin; the walk decodes through
the instruction-set plugin, x86: capstone), `S.entry.dllmain`
(the non-library call target of `_DllMainCRTStartup`), `S.pubsrc` (catalogue version strings → public-source
candidates; compiled candidates scanned like lib members), `S.probe` (`dcp toolchain probe`: compile anchors —
CRT sources if present, public-source hits, later every matched function — under the flag grid `/O1 /O2 /Ox ×
/G3..G6 × /Oy /Oy- × /Gy × /GF /Gf × /Ob0 /Ob1`; each flag reports *distinguished by N anchors* or
*indistinguishable*; the toolchain fact becomes proven only for flags distinguished by ≥ 2 units), `S.unknown`
[open] catch-all, `B.bytemap`. Checks: `C.overlap`, `C.ref.target` (call into the middle of a proven function),
`C.reloc.unmasked` [bug], `C.toolchain` (per target: the declared compiler / linker build is one of the Rich
header's compiler / linker candidates, a missing declaration or reason is an error), `S1` sizes vs file, `S2` Rich
counts (compiler entries of other builds than the declared one) vs members found, `S4` import DLL without import lib, `S5` unexplained gap in the CRT region, `S7` export/entry outside
`.text`, `S8` public-source string without a compiled match.

`dcp toolchain [--target]` prints the evidence view per target: the declaration (and what it inherits), the Rich
candidates and the C.toolchain verdict / archives and libs (members matched) / probed (anchors, units, flags
distinguished) and which flags are still declared only.

**Layout `L.*`** (`dcp layout ...`): loaders `L.decl`, `L.src`; `L.analyze` once per image hash: starts with
their evidence (export / entry / call / immediate / reloc-pointer / ghidra-declared), call graph, fill runs,
**literal-pool order** (per function the sorted data targets of its reloc sites, per literal its first user; exact
for a DLL), string xrefs, an analyzer's bulk export (REA `batch_decompile` files first; Ghidra's headless
`analyzeHeadless` script later; since the amendment of section 12 the analyzer seam run by `dcp setup`) stored as
blobs by (image hash, start). Boundary evidence rules: `B-LEAK` leaked
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

Every command takes `--target NAME` (section 1.5). `dcp init [--from-setup]` · `dcp target add|list` · `dcp setup [--all-targets] [pe|dirs|rich|strings|sigs build|sigs scan|entry|probe|report]` ·
`dcp toolchain` · `dcp why ADDR` · `dcp facts LO..HI [--kind]` · `dcp conflicts` · `dcp rules` · `dcp check
[--strict] [--against REV]` (the gate: loaders parse, no conflicts, every TU compiles, link resolves, no grade fall,
decl files sorted, UTF-8/LF) · `dcp decl add "LINE"` · `dcp layout next|units|unit propose|analyze` · `dcp
draft [--show]` · `dcp build` · `dcp link` · `dcp unit cat|fold` · `dcp grade [NAME|UNIT]` · `dcp next` · `dcp
escalate|stuck|accept` · `dcp promote` · `dcp rename OLD NEW --why` (the only way to rename: edits sources,
appends to `names.log`) · `dcp claim` · match toolbox `dcp asmdiff|diffclass|spell|idioms|siblings|slotmap|
listing|try|vargen|respell|tuorder|c2prio|dump|refs|data next|data table` · `dcp wt new|list|drop|seed` · `dcp
merge BRANCH...` · `dcp session prepare|wrap|report|close` · `dcp lint`.

## 4. Parallelism and merge

- **Files**: one file per unit (section 19; one function per file before) → one worker per unit; a unit's file
  is that worker's alone, headers and `.dcl` files are the only shared ones and change additively (sorted
  inserts).
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
    image/    __init__.py base.py pe32.py     # Image seam (sections, dirs, regions, imports, exports, relocs, rich, read); registry
    objfmt/   __init__.py base.py coff.py     # ObjectFormat seam (.obj, .lib archives, relocation view)  ← port of link.py Obj/archive_members
    toolchains/ __init__.py base.py vc6/{__init__,cl,rich,link}.py   # Toolchain seam: fill forms, import stubs, entries, Rich, defaults,
                                              # later compile, includes (CL /P), link
    isa/      __init__.py base.py x86.py      # Isa seam: instruction records for the walk (x86-32: capstone; blob memo with M3)
    build/    compile.py amalg.py link.py
                                              # every seam package keeps a registry its plugins register into
                                              # (docs/architecture.md: what each exposes, what the rules may know)
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
| M2 declarations + layout | the target dimension (section 1.5: `[[target]]`, store per target, `--target`, target prefixes in the address-comment and `.dcl` grammars, `dcp target add`), `decl.py`, `srcscan.py`, `L.*`, boundary rules, Ghidra import, `dcp layout *`, `dcp decl add`, `dcp check` (loader + conflict gate), `dcp wt new/seed` (overlay store) | first unit declared on server.dll from `Init` outward; a deliberately wrong boundary and a walk crossing a start are caught (L1/L3/L4); a second target added to a scratch project gets its own store and `dcp why --target` answers for both |
| M3 build + compare + grades (done 2026-10-29) | `toolchains/vc6/cl.py` (`/E` include sets: the `/P` listing on stdout), pool compile, amalgamation, `M.match` with reloc aid, `M.draft`, `M.data.site/.content/.draft`, capstone asmdiff/diffclass, `G.grade`, `ledger/grades.tsv`, `dcp build/link/grade/next/promote/escalate/stuck/asmdiff/diffclass/lint`, full `/DLL` link with generated `.def`, lint, checks M1, M2 (stale / double level tag), M5..M10, D1, D4..D6; open: M3, M4, M11, M12, D2, D3, `M.data.iat/.lib/.fill`, `M.bytes.declared` | first functions byte-match (server.dll DllMain / Init / Exit, relocs 0/0, 2/2, 4/4); `dcp toolchain probe` runs the grid and says *indistinguishable* for most flags with three anchors from one unit (correct: proven needs anchors from two units); a header edit recompiles only its includers (shown) |
| M4 layout tooling (done 2026-10-29) | Ghidra headless export (since the amendment of section 12: the analyzer seam inside `dcp setup`, its lines in `dcp report`), L9, reading tools (`dcp disasm`, `dcp dump`, `dcp refs`, `dcp layout literals`, `dcp layout starts`), drafting (`dcp unit new`, `dcp unit join`, `dcp unit rename`, `dcp draft [--next]`, `dcp rename` + `names.log`), unlinked helpers and `bytes dead` in the unit byte map, L10, `dcp session start`, `dcp session wrap`, the skill `dcp-layout` (`dcp init` / `dcp skills install`) | on a scratch project of server.dll: export, status, starts / literals of a range, the first ten minutes of a layout session (unit new, five drafts, build, grade, refs, rename, unit rename, check, session wrap); shown: 678 Ghidra drafts in ~30 s (all 311 game functions), four units declared around 0x10001000 (zlib's adler32 and crc32, a broadcast helper, deflate), five drafts, two of them byte-identical after the hand fixes, `dcp check` and `dcp session wrap` ok with the undrafted externals classified |
| M5 layout experiment | the user runs layout sessions on server.dll (`../guild-server`) by hand with the skill; findings go back into the tooling | the units of server.dll's game code drafted and separated, the session reports computed |
| M6 match toolbox | try/vargen/respell on fragments with the shared pool and hash cache, listing, slotmap, siblings, spell/idioms catalogue, tuorder, c2prio plugin, `dcp escalate/stuck/accept`, `dcp data *` | a respell round on a shape-grade function runs with cache hits for repeated variants; deep queue reproducible |
| M7 parallel sessions | the `names.log` fold at the merge (the log and `dcp rename` itself are M4), claims, `dcp merge`, `dcp session *`, skills, pre-commit hook | two worktrees rename one address differently and edit neighbouring functions; `dcp merge` resolves without hand conflicts; G3 passes; a full /dcp-session round on server.dll |
| M8 second target | GildeGold.exe as a second target of guild-server (the target itself, its toolchain declaration and archives, setup and the gate run since the multi-target round of 2026-10-29: game code 0x401000..0x5dd3e0, CRT from 0x5de4a0; open: the exe has no `.reloc`, so W3 finds nothing and ~0xc6000 bytes of its game code stay unknown — a `.data` ordered literal scan and code-pointer evidence replace the reloc evidence), rule `X.same.code` (section 1.5) transferring names, sources and the dll's data references to the exe's identical functions; amended 2026-10-29: `rea` is migrated after all, into its own project `../gildegold` (section 13) | setup report rediscovers notes/binary-facts.md (zlib range, CRT start 0x5de4a0, VC6 SP5+PP /O2); every exported or CRT-named dll function with an identical copy in the exe is named there at the proven level |
| M9 gap data | (section 14) the gap ledger (`D.gap`, `dcp data gaps`): the bytes of the data sections no definition covers, with their users and owner candidates; `dcp data claim` (name, type, size, owner by address order: splits the gap, moves the definition, writes the one header declaration, rewrites the externs and the use sites; dry run unless --write); then the generated gap block and gap header under build/ in place of gildegold's hand-kept block in src/main/tail.c and the `extern GAPDATA` lines of the heads | on gildegold: a claim of a `full_data_` gap used by one unit moves it with `dcp check` unchanged (no new D1 / D4, no M1, the users still match); a claim between two units' blocks is refused with both candidates and their evidence; with the generated block the 707 definitions and ~990 extern lines are gone from src/ and every byte match is kept |

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
(`names.log` + N1 cross-check); "behaviour" grade name (overclaims: "shape"). Of the second (section 19): one
file per function through a generated amalgamation (merge-free in git only; two workers in one unit still
interfere in the bytes, and the composition, order files and `#line` segments cost more than they bought).

## 10. First implementation step (after approval)

Create `C:\Users\andre\Documents\decompanion` (git init, uv init with Python 3.15, LF/UTF-8 config), implement M1
in this order: `fact.py` → `store.py` → `engine.py` (+ tests on toy rules) → `image/pe32.py` (server.dll +
GildeGold.exe fixtures) → `objfmt/coff.py` (LIBC.LIB) → `toolchains/vc6/{rich,fill}.py` → `disasm.py` → `S.*`
rules → `B.bytemap` → checks → CLI → `dcp init` producing `../guild-server`. Verify with `dcp setup` on
server.dll as in the M1 row, then `dcp why 0x10001000`, `dcp why <Init>`, `dcp conflicts`, and a rerun showing
zero rule runs.

## 11. Milestone 3 as built (2026-10-29): what changed against the plan, and why

- Include sets come from `CL /E` (the `/P` listing on stdout) instead of `CL /P`: the same `#line` directives
  without a `.i` file next to the amalgamation.
- The store keeps one `tu` row per unit (store per target, so no target column) and an `include_set` table;
  both are created by `CREATE TABLE IF NOT EXISTS`, the schema version stays 1 (existing stores stay valid).
- The compile is not a rule: `dcp build` (and `dcp check`, `grade`, `next`, `link`, ...) runs it, the rules read
  its outcome through the input `objects` (the hash of the tu rows and whether the toolchain is installed).
  `M.compile` turns the rows into `build` facts. Rules never run a tool; `dcp why` never compiles.
- `M.match` emits a proven `symbol` func up to the last non-fill instruction (CL pads a function's COMDAT with
  fill to the next alignment; the fill keeps its derived symbol) and a proven `source` fact (what: match) over
  the section; `M.draft` emits `source` (what: draft). The layout view and the setup report ignore the match
  phase's duplicate function symbols.
- R1 adds a tail check: the original must not continue after our last byte (only fill up to the next start),
  else a shorter function whose bytes equal a prefix of the original would count as a match.
- The probe grid adds `/GB` (VC6's default `/G` setting; without it a declaration naming no `/G` option is not
  in the grid) and breaks ties by the declared flags, then the compiler's defaults. A flag is distinguished only
  when every other value of its group loses an anchor. CRT sources are compiled as anchors but reported apart
  (another compiler build, the library's own flags: they prove nothing about the user's units).
- S.codewalk v3 (W4): a known start directly after a call ends the function (the callee does not return). With
  server.dll's true CRT (LIBCMT: `_beginthread`; 109 members placed against LIBC's 75) the walk otherwise ran
  from `_threadstart`'s handler into `_endthread` and failed the gate with C.walk. The setup facts of the
  scratch projects are byte-identical apart from the producer `rule:S.codewalk@3`.
- The level tags are removed by `dcp build` when a function reaches byte + readable (auto-clear); a remaining
  stale tag is the warning M2.
- The toolchain not installed: units are not compiled and M.compile warns instead of failing the gate.
- Open (M6 or later): M3 (stuck without open.md), M4 (distance WORSE without `dcp accept`), M11, M12 (the
  header-commit distance check), D2 / D3, `M.data.iat` / `.lib` / `.fill`, `M.bytes.declared`, `dcp accept`.

## 12. Milestone 4 as built (2026-10-29): what changed against the plan, and why

- Ghidra's export (a command of its own at first; since the amendment below the ghidra analyzer inside `dcp
  setup`) seeds Ghidra with our starts: the post-script creates a function at every start of ours Ghidra lacks
  (tagged `DCP_SEEDED` in the Ghidra project, `seeded` in the JSON) before decompiling, so every
  function of the game code has a draft (server.dll: 311 of 311; without the seeding 232). A seeded function is
  no claim of Ghidra's and gives no `start how=ghidra` fact. The export is keyed by (image, script, our starts).
- L9 is a warning, not an error, and only for Ghidra functions of the game code: Ghidra's body is an external
  tool's analysis; in the library code its merges (assembly CRT routines) are no layout question. On server.dll
  all eleven L9 cases lie in the CRT.
- L10 is a warning for code a fragment claims but nothing explains: a fragment in unknown code that does not
  byte-match (no walk extent for M.draft) or a byte match whose walk runs past its section. "Walked code reached
  from nowhere" as planned does not occur: every walked function is reached from some evidence.
- A unit's status: C.walk conflicts inside keep it open (rule `unit_status`); undrafted functions (L2) still do
  not (unchanged from M2; `dcp layout units` counts them).
- `M.bytes.declared` (R5) is a rule of rules/layout.py: declared dead / foreign bytes inside a unit get a
  `source` fact {what: dead, unit} (the byte map gives them the unit) and count as `dead_bytes`.
- The link: an unresolved placeholder (or registered name) of an address the sources do not define yet is the
  class `undrafted`, and an export without a fragment is left out of the generated .def; neither fails the link.
  Without this every layout draft (calls into undrafted functions, `DAT_` data) failed `dcp check`. The cached
  link result is classified again on every read (the classes follow the current facts).
- Seams: Isa `disasm` / `numbers` (reading) and Toolchain `declaring_header` / `import_header` (drafting).
- `dcp rename` replaces whole words in code and comments but not in string literals or `#include` lines (a unit
  named like a function, `adler32` / `adler32.h`); a collision is an identifier of the code only. `dcp rename`
  and `dcp unit rename` rebuild afterwards (M.gen compares objects with fragments).
- `dcp layout unit propose` fails only on errors of its own lines (before: on any error of the store, so a unit
  that was not compiled yet made every later proposal fail).
- The skill lives in the repository's `skills/` (not under the package's data/): decompanion is installed by
  path, `dcp init` and `dcp skills install` copy it into `.claude/skills/`. `dcp-match-base` waits for M6.
- Open after M4: the hand fixes Ghidra's C needs (struct tags, partial field access `._2_4_`, register
  variables) are left to the agent (the skill lists them); data placeholders are typed by Ghidra's label prefix
  only; `dcp unit new` without an end lists every function to the end of the game code.

Amended 2026-10-29 (user decision): Ghidra is neither a toolchain nor a language property but a third-party
**analyzer**, the fifth plugin seam `analyzers/` (registry and `@register` like the other four; docs/architecture.md):
`ghidra` (the headless run, the post-script and `dcp_ghidra.h` referenced only from analyzers/ghidra.py, the
language id from the instruction set), `rea` (saved `batch_decompile` files, `[analyzer] file`, Ghidra's dialect by
subclassing), `none` (no drafts: `@rough` skeletons). `[analyzer]` (plugin, root, java_home, timeout, file; default
plugin ghidra; `dcp init` writes what it finds, else `none`) replaces `[ghidra]`. The analyzer runs inside `dcp
setup`: the rules, then the export when its key (analyzer, image, script hash, our starts) is stale, then the rules
again (only `L.analyzer`, L9 and the rules needing every start, L4 / L5); `--no-analyzer`, `--analyzer-force`; a
missing installation is one warning line and setup still exits 0. The stored entries are the generic input `drafts`
(ledger/drafts.py; an export replaces them); `L.ghidra` became `L.analyzer` v3 (declared, `by
decl:analyzer:<key>:<file>`, reason `<key> analysis`, `how` the key), the L9 rule reads `drafts` (`L9.analyzer.span`
v2), names of the analyzer have the origin `analyzer` and its placeholders come from the plugin. source/draft.py
composes the analyzer's dialect in (rewrite, data_labels, types_header) with the toolchain's language out (Toolchain
`keywords`, `default_convention`, `sized_conventions`). The Ghidra commands are gone: export and import are
`dcp setup`, status is the analyzer line of `dcp report`, show is `dcp draft ADDR --show`; `dcp session start`
prints the analyzer. Shown on a fresh scratch project of server.dll: cold setup 33 s (the rules 1.3 s, Ghidra
31 s, the second rule pass 4 rules in 53 ms), 678 drafts, every one of the 311 game functions drafted, 6
analyzer-only starts in library code, l9=0, the export byte-identical with the last round's; warm setup ~0.39 s
(~0.37 s without the analyzer step); the setup facts of m5 / m2 byte-identical.

Amended 2026-10-29, guided decisions (user decision). decompanion must guide the user through every decision of the
decompilation, not take decisions for them: "`dcp init` declares nothing. Every human decision is an **obligation**
that the tool names when it becomes due, with the evidence it has, the command that resolves it, and the check that
verifies it afterwards. Init only records the binary." The reason: `dcp init` required `--toolchain-root`,
pre-filled compiler / linker / cflags from the Rich header with a "verify" reason, and defaulted the archives to
LIBC although server.dll links LIBCMT (the user had to be told to hand-edit the toml). As built: `dcp init DIR
BINARY [--target-name N]` writes the `[[target]]` (name, path, sha256, image, isa: computed) and the `[analyzer]`
the machine has (unconfirmed), nothing else; `dcp target add` likewise. obligations.py computes the obligations
from the configuration and the store (never stored): toolchain.compiler, toolchain.linker, toolchain.root,
toolchain.cflags, libs.archives (due once the root is declared), analyzer, layout, match; `dcp status` prints the
phase and the open ones in order, `dcp setup`, `dcp session start` and every declaration print it as their tail;
the toolchain and libs obligations fail `dcp session start` and `dcp check`. The declarations `dcp toolchain
declare KEY=VALUE... --why`, `dcp libs declare ARCHIVE... --why`, `dcp analyzer declare PLUGIN [KEY=VALUE...]
--why` write `reason.<key>` per key (tomledit.py keeps the comments; the older `reason = "..."` still reads as
every key's) and rerun the rules. The evidence: `dcp toolchain` (the declarations per key with level and reason,
the installs the toolchain plugin finds with the versions of their tools, the Rich candidates with the build names,
the PE linker version and time stamp, the CRT strings) and `dcp libs candidates` (build/libcand.py: every run-time
archive of the root placed on its own with S.crt.code's search, now `place_members` in rules/setup.py, cached per
image and archive). The setup runs in two stages: an input absent until declared makes its rules wait
(rules/engine.py: an empty run keyed by the obligations, `waiting:` in `dcp rules`); S.rich reads the new input
`archives` (the declared archives or none), so the Rich candidates are there before any declaration. Found on the
way: CL.EXE reports 12.00.8804 in both installs (the driver); the Rich compiler build is the back end's, C2.DLL's
(SP5 + PP 13.00.9044, SP6 12.00.9782), so the installs are read from the version resources of CL / C1 / C2 / LINK,
not by running them; the debug CRTs place members too (LIBCMTD 21, LIBCD 19: the assembly routines are
byte-identical), LIBCMT 109 and LIBC 75 conflict on 6 places; the stage-1 export seeded Ghidra at starts the CRT
placement later removes, and a reused Ghidra project kept those functions (682 drafts, two declared sizes changed),
so an export whose previous seed is no longer a subset of our starts is now `fresh` (meta `drafts.starts`; the
project is imported and analysed again). Shown on a fresh scratch project of server.dll on the user's path
(build/scratch/m6.sh): cold setup 29 s (the rules 1.6 s, Ghidra 27 s, 7 obligations, 8 rules waiting, 8 C.overlap
errors in the unplaced library code), the toolchain declaration reruns 12 rules in 0.3 s, `dcp libs candidates` 1.0
s cold / 0.3 s cached, the libs declaration 34 rules in 1.4 s, the next setup 27 s (the fresh export, 678 drafts),
warm setup 0.35 s, `dcp session start` gate ok, the m4b layout sequence to `dcp session wrap` gate ok; its facts
equal the last round's m4b apart from the four object hashes of M.compile (the objects hold the compile time stamp
and the project directory, m6 vs m4b), its conflicts (16 warnings) and unit table byte-identical; the setup facts
of m5 / m2 byte-identical.

## 13. The migration of `rea` (2026-10-29, user decision): what the framework gained

The user decided to migrate the first attempt now (match toolbox later, M6): GildeGold.exe is the target `exe` of
a new project `C:\Users\andre\Documents\gildegold`, converted by its `tools/import_rea.py` (rea-specific, so
not in decompanion: one rea unit file -> head.c, f_<addr>.c, u_<name>.c, tail.c; @named_by / @boundary /
@bytes -> decl/text.dcl; zlib's #if groups that cross a cut resolved to the compiler's branch, checked by CL /EP).
Byte parity with rea's baseline: 2664 of 2664 functions, every unit compiles. What the framework gained:

- `src/<unit>/order` (L12): the TU order when it is not the address order. Address order alone (the user's
  first choice, tried) left 7 units uncompilable and changed two byte-matched callers in `am` (a callee
  defined above its caller changes the caller's code; rea had moved it on purpose).
- `__inline` helpers are not counted as functions (no symbol, no address; 15 in rea).
- N2 compares `static` names within their unit (vfs.c and gzio.c each keep a `gz_magic`).
- COFF function_code: a `$L` label (CL's switch table after the code, a static symbol) no longer ends a
  function (38 byte matches with switch tables failed the tail check).
- Walk convention W5: an unconditional jump followed only by fill up to an aligned target is a tail call (exe without
  base relocations: zlib's `_tr_init` -> `init_block`).
- `dcp link` builds an import library a DLL lacks from the image's import directory (`make_import_library` of
  the toolchain seam; mss32.dll), import records carry their hint.

Added after the migration commit (user decision: the framework pieces first), closing M9 and L1 of gildegold:
- decl kind `file` (data.dcl, at the `__FILE__` string's address, checked against the image): the
  amalgamation numbers its parts on behind `#line n "<original name>"` and maps the diagnostics back
  (Amalg.segments; a `#line N` pin starts a segment). The M9 message proposes the line.
- the walk takes decl `start` lines as roots (own loader L.decl.start, so boundary edits do not rerun the
  walk); facts resting on a declared start are declared (premise propagation through calls, tails, immediates).

Added next (user decision: the data tooling first, then validate it; "all the tooling has to be fast"):
- `dcp data map`, `dcp data fix` (docs/match.md): trial compiles decide per edit group; on gildegold the
  data errors went from 616 to 9 with every byte match kept, the remaining 9 rejected with their reason.
- D1 / the data extents use the least size (an object's COFF size includes the alignment padding before the
  next symbol); D4 ranks by the amalgamation's order.
- Speed (a one-file edit, compile + refresh, warm): ~17 s -> ~6 s: per-file source scan cached by content hash
  (build/cache/srcscan.pickle), the readability context collected by the scan and each function's readability
  in the blob store, each include directory's listing hashed once per run, compiled_functions shared by the
  rules of one refresh, decoded facts cached per (run, kind), files read once per process (fsmemo.py).
- Correctness: `refresh` drops the memoised src / decl input hashes, so a command that wrote sources no longer
  refreshes against the old tree.

Library units (user decision, instead of a fragment of a game unit for library code): decl `libunit
lib=ARCHIVE tu=UNIT` over a library member's range; the unit is no game unit, L14 checks its fragments against
the range, and `dcp link` adds its object to the archive (Toolchain.add_library_members: LIB.EXE), so the
relinked image keeps the member among the library contributions instead of shifting every later unit.
gildegold's mss32.lib code member (MSS_auto_cleanup and its exit callback) is the first: both byte, and in the
relinked exe they sit between the DINPUT stub and the AIL_shutdown thunk as in the original. Seen on the way:
LINK places LIBC's members before the import libraries' contributions, the original after them (library order,
open for whole-image identity).

Left open, visible in `dcp check` of gildegold (the user accepted gate=FAIL for the migration commit): rea's
data debt (D5 tentative definitions 530, D4 69, D1 9, M.data.content 1, data C.overlap), and the link's
unresolved names (CRT functions
under placeholder names, an ICF-folded stub, GUID libraries not declared, two Miles stubs) that rea resolved
with hand-written alias tables.

Added next (user decision, 2026-10-30: a gildegold session made four decisions that passed with gate=ok; each is
now caught):
- A1 (`A1.addr.cast`, error): an integer literal inside the image cast to a pointer type (`atexit((void
  (*)(void))0x5de470)`); the relinked image places the object elsewhere. The source scan collects the casts per
  file (srcscan.PTR_CAST, cached with the scan), so the rule reads no file. gildegold: 5, all in
  unk_575860/f_580a50.c (`*(int *)(0x6f9f60 + i * 0x38)`).
- L13 (`L13.data.code`, error): a data definition or extern whose address is a known function's start or inside
  its extent (`extern char ai_SeanceDecideStub[]; /* 0x52a040 */` at sv_ReturnZero). gildegold: 0 now, 2 at
  98fca9c.
- L14 (`L14.unit.outside`, error): a fragment in the library code whose unit has a declared extent elsewhere
  (L7 looks at the game code only). gildegold: 2, mss32.lib's MSS_auto_cleanup / its exit callback in unit sfx;
  gildegold's gate fails on them until the project decides where library code that has a source lives.
- The link's class `library`: an unresolved name an undeclared archive of the library directories defines
  (DX6's dxguid.lib for `_IID_IDirectDraw4`, which VC98's DXGUID.LIB lacks), with the `dcp libs declare` that
  adds it; it reopens the obligation libs.archives. The archives' first linker members are indexed once per
  content hash in the blob store, and only when such names remain.
- The warm `dcp check` of gildegold is unchanged (~5.2 s).

Added next (user decision, 2026-10-30: "it needs to be as fast as possible for fast feedback loops"; the
architecture chosen: a resident daemon plus the loop fixes; eager background compiles and per-unit rule partitions
later). Measured on gildegold with tools/bench.py (one-line edits of a function's fragment, applied and reverted):
- `dcp serve` (daemon.py, client.py): one process per project root on a named pipe; the `dcp` script forwards
  argv, cwd and environment and streams stdout / stderr back. Requests run one at a time; a changed decompanion
  restarts it (the supervisor around the daemon process; the client waits and sends the command again). What it
  keeps is what the process memos keep, all keyed by content: no request sees an older state than a new process
  would. Mandatory since 2026-10-30 (user decision: "make starting the dcp server mandatory"): without a daemon a
  command fails and names `dcp serve`; the in-process fallback and DCP_NO_DAEMON are gone (only `dcp init` and
  a command line outside any project run in the client's process).
- fsmemo: one stat per file per epoch (a directory listing gives the stamps), content hashes persisted per
  project with git's racy rule; tree_hash, the source scan, the lint and the word scans of `dcp rename` read
  only changed files. A plan per source state; the amalgamation's text is composed only for a unit that compiles
  (its hash is memoised by its parts' hashes).
- compiled_functions compares one function once per (object, symbol, address, next start, image, relocations);
  M.match memoises the end of a matched function's code; G.grade its code grade row and readability.
- record_run keeps the facts (and ids) of a run whose output did not change; the byte map is rebuilt only when a
  run holding map facts was recorded again.
- `dcp build` lints the units it compiled before its one refresh (grade / next lint no more); `dcp rename`
  refreshes once after its edits and fails only on errors it caused (feedback item 8).
- Found on the way: SQLite reuses a deleted run's id for the next run, so the decoded-facts memo keys on
  (id, time); compiled_functions' memo returned fact objects of an older L.src run with the same addresses.
- Result (median, warm daemon): build after an edit 7.5 s -> 1.8 .. 2.8 s (CL 0.55 s, the refresh ~1.1 s),
  diffclass / asmdiff / grade / next / dump / why 1.2 .. 6.1 s -> 0.2 s, rename 13 s -> 3.6 s. In-process
  (no daemon): build after an edit 7.5 s -> 5.0 s, diffclass / asmdiff / grade / next 2.2 .. 6.1 s -> 0.6 s,
  dump / why / draft --show 1.2 s -> 0.55 s, rename 13 s -> 6.2 s. `tools/bench.py --verify` (a forced
  recompute in a fresh process, DCP_NO_SHORTCUTS=1) agrees with the incremental store after every scenario.

Added next (2026-10-31, after a gildegold match-base session: 191 calls, 612 s of tool time, rename 47 % and build
41 %): the fold to one file per unit had made the loop slower again, and tools/bench.py still looked for the
fragments. The bench now edits a function's span in src/<unit>.c (S3: a blank line above the address comment,
only line numbers move), and S6 / S7 rename three names in three calls / in one. What changed:
- `dcp rename OLD NEW [OLD NEW ...]` and `--from FILE`: every pair is checked before anything is written (one
  refusal refuses the call), the pairs are written in one pass, then one rebuild and one check for all of them.
- srcscan.local_refs parses one unit per file that holds a name (a unit file itself, a header through the first
  unit that includes it), not every unit that includes such a header; the word scans of rename test the
  substring before the regex. Rename's own work: ~2.1 s -> ~0.5 s for three names.
- G.grade: the file memo held 64 files (gildegold has 93 units), so every run lexed all of them again; the lines
  are memoised apart from the lexed file (a memo hit needs the lines only); the code and readability memos keep
  the last run's entries when they grow past their limit instead of clearing. ~0.5 s -> ~0.17 s.
- build: the compiler's include scan (CL /E) runs beside the compile, not after it; tu.segments is memoised per
  text (each of a unit's diagnostics split the 4000-line file again); the lint's all-declarations unit takes its
  header models with the target's defines, the source scan's, so a header edit no longer parses each changed
  unit once more without them.
- Result (gildegold, warm daemon, median of 2, the first number before): build after a body edit 3.0 .. 3.8 s ->
  2.0 .. 2.8 s, after a line move 4.0 .. 6.0 s -> 2.9 .. 3.7 s, after a header edit 4.5 .. 5.8 s -> 3.1 .. 3.9 s;
  rename 7.5 .. 9.5 s -> 5.1 s; three names 3 x 7 .. 12 s -> one call 7.2 s. `--verify` ok after every scenario.
  What is left is in docs/feedback.md (the rules that rerun whole after a compile or a line move).
- The source scan's model walk is native (2026-10-31, user decisions: "go ahead with native helper", "no
  fallbacks"): clang parses a 10000-line unit in ~0.1 s, but the walk of its ~50000 top-level cursors (most of them
  macro expansions) through the Python bindings took ~0.35 s more. data/native/dcp_clang.c walks them on the
  bindings' translation unit and returns one text record per cursor the model reads, with raw positions;
  cparse.model maps them as before (casts, skipped ranges, includes and diagnostics stay on the bindings: a few
  calls). Built on first use with gcc and the LLVM headers; no Python walk remains. Checked before the switch: the
  model of all 202 files of gildegold (units and lone headers) equal to the Python walk's. Model per unit 0.45 ..
  0.65 s -> 0.15 .. 0.22 s; the worst case measured, a comment line in gildegold's d3.h (43 units compile), 12.5 ..
  12.9 s -> 9.5 s (plan 3.5 s -> 1.2 s; left: CL 5.0 s, lint 1.65 s, rules 1.5 s).

## 14. Gap data (M9, planned 2026-10-30, user decision): what the framework takes over from the projects

The full link must lay out every byte of the data sections, also the bytes no definition covers yet. gildegold
inherited rea's answer as source: 707 `GAPDATA full_<sec>_<addr>[N] = { .. };` definitions in a generated
block at the end of `src/main/tail.c` (rea's tools/full_addrs.py; `#define GAPDATA __declspec(align(1))
unsigned char`), ~990 `extern GAPDATA full_..[];` lines in 11 unit heads, and the rules in
gildegold/notes/rea/campaign.md: the block is packed (VC6 aligns an object of 8 bytes or more to 8 and every
object to 4, so unpacked gaps grow padding the ledger reads as part of the item before it: ~1300 overlap
errors), each size is the exact distance to the next known address, the externs carry the alignment too (VC6
takes an object's alignment from its first declaration), and the macro exists because `gen` takes a `(` in a
declaration for a prototype. The tools that made the block (gap_fix.py, full_addrs.py) stayed in rea; in
decompanion only Q2 knows the names (it flags `full_data_*` as placeholder identifiers). A match-base session
(2026-10-30) showed what that costs: a gap that a worker named kept its untyped `GAPDATA` form in several heads
(`main_NetHost`, `main_NetSaveName`, `main_NetGameRecord`), and the skill now carries a long paragraph of
by-hand steps (dcp-match-base 2.5, "Gap data") for what is one mechanical operation plus a judgment.

What a gap is: bytes of the original's data sections that no symbol of ours covers. Name, type, extent and
owner are all unknown; a gap runs to the next known address and may hold several objects; its place in main's
tail.c says nothing about ownership. The owner follows from the address: VC6 lays out one object's data
contiguously in link order, so an address between two definitions of one unit is that unit's.

Steps, in this order (the second is useful without the third):
1. The gap ledger. Rule `D.gap` [derived]: the ranges of the data sections no definition covers (least size,
   as D1), with the unit blocks they lie in or between (the unit data blocks of `dcp layout literals` and
   `dcp data map`). `dcp data gaps [UNIT|LO..HI]`: each gap with its range, its users (functions, units) and
   the owner candidates with their evidence (`owner=<unit> by=between|users` or `owner=? between=A,B`).
2. `dcp data claim ADDR NAME TYPE [--size N] [--unit U] [--write]`: checks the owner (refuses an address
   between two units' blocks with users in both, printing both candidates and their evidence, unless `--unit`
   names one), splits the gap (the rest stays a gap at its own address), places the definition in the owner's
   head.c / tail.c in address order with its address comment and the original's initialised bytes in the
   type's spelling, writes the one declaration into `include/<unit>.h`, drops every `extern GAPDATA` of the
   claimed range and rewrites the use sites (`(unsigned)&full_data_X` -> `&NAME`, `U_I(...)` -> `NAME`, an
   offset into the gap -> the field or element); then the trial compile and `dcp check` of `dcp data fix`
   (datafix.py) decide: no new D1 / D4, no M1, the users that matched still match (`M.data.site`), else
   nothing is written and the refusal says which check failed. Dry run by default, like `dcp data fix`.
3. The generated gap block. The ledger's gaps become an object of their own, generated under build/ (the
   `GAPDATA` definitions packed as today) with a generated header of the `extern GAPDATA` declarations that the
   amalgamation includes; gildegold's block in `src/main/tail.c` and the externs in the heads go away, and a
   claim shrinks the generated block by itself. The `full_<sec>_<addr>` names stay (they hash the address, so
   use sites in src/ stay valid). Open: where the gap object goes in the link order. Today the whole block
   sits in main's object, so the relinked image places every gap after main's data, not at its address; a
   gap object per unit block (or the gaps of a unit emitted into its amalgamation's data after its own
   definitions) moves toward whole-image identity, and a gap between two units' blocks needs its own object
   in the link order between them. Decide with the link's data-placement report before building it.

Then the skill's "Gap data" paragraph becomes "settle the name and the type from the users and the bytes, then
`dcp data claim`", and the layout passes keep only the boundary cases (`owner=?`).

## 15. Header typing (2026-10-30, user decision: "extend dcp tooling now")

A typing pass on gildegold's `src/main/head.c` (19 headers included, 84 copied prototypes and 6 local struct
views dropped, every byte match kept) was driven by a by-hand trial script; it is now `dcp headers conflicts
UNIT HEADER.. [--write]` (source/headers.py, docs/match.md "Lint"): a trial parse of the unit with the
includes, the new diagnostics classified (supersedes / duplicate / clash / header / call with the original's
pushes and `add esp` / prototyped / other; a clash whose side carries `@original` is marked), the functions to
re-grade, and `--write` for the include when only duplicates are in the way. About 1 s a unit.

Open:
- Done (user decision: "fix the checks even if gildegold then fails"): M5 counts struct / union / enum and
  typedef redefinitions between headers, an `@original` / `@vc6` exemption no longer applies between two
  headers, and `@private UNIT[,..]` marks a header the original only included into some units (left out of the
  all-declarations unit; another unit including it is M5). gildegold's gate: ok -> FAIL, 86 M5 (78
  `@original` spellings in shared headers, 8 tag / typedef redefinitions, 2 of them zlib's `internal_state`
  that `@private` answers).
- The header consistency pass (project work in gildegold): ch.h vs d3_engine.h (D3OBJBITS), d3_anim.h /
  ch.h vs d3_engine.h / d3.h (d3anim_* with `@original` spellings: two headers that cannot be included
  together, so the unit-specific spelling belongs in the unit that needs it, not in a shared header), mem.h
  vs vfs.h (MPOOLITER), d3_d3d.h vs dd_vesa.h (dd_SetSurfaceName), the ai_Time / ai_Chars / ai_BTypes shapes
  of hmt.h, hst.h, ahm.h, amt.h, gv.h, cm.h against ai.h; headers for sblib, d3_snd, sv, f3init, io_text,
  d3_tools, ls. Then the dedicated head passes of unk_58bbd0, he, unk_575860, sv (the base queue's largest
  units).

## 16. Debt guards (queued 2026-10-30, user decision: "queue them before the debt worker")

The M5 pass in gildegold (fb5bb02 .. 520c492) left debt that every current rule accepts (gildegold
notes/headers.md): consistent but weak spellings, agreeing copies of other units' symbols, and 155 cast / view
macros. M5 checks that declarations agree, not that they are the right ones. Four rules, built after the M5
per-symbol work (section 15's follow-up: M5 knows each symbol's definition) and before the debt pass, so the
debt shows as errors and the gate keeps it from coming back:
- **Copy rule:** a header or head.c / fragment declares a function or datum defined in another unit, where the
  owner's header exists: an error unless the unit includes the owner's header instead, or the copy carries
  `@keep why` (the VC6 declaration-set effect, with the function whose bytes move, is one such why). Without an
  owner's header: a warning naming the owner unit (it needs a header).
- **View-everywhere rule:** a datum that most of its readers reach through one view type T (`(*(T *)&datum)`),
  or a parameter every caller casts to its declared type (`(int)vfs_Root`) or the definition casts on entry:
  "retype the definition to T" (warning; an error when every reader / caller does it).
- **Macro evidence rule:** a cast or view macro in a head (`#define X ((T (*)(..))f)`, `#define X (*(T *)&d)`)
  carries `@original` with an address of the original whose bytes need it, else an error.
- **Debt count:** per unit, the cast / view macros, `@keep` copies and `@original` exemptions in `dcp status`
  (and the session wrap), so the debt stays visible as it is paid down.

## 17. Accepted falls (queued 2026-10-30, user decision: "queue both"; done 2026-10-30)

M1 holds every function at its baseline grade (ledger/grades.tsv); the only way past a fall is `dcp promote`,
which rewrites the whole baseline and accepts every current fall at once, without a reason. The header
passes in gildegold met a fall the user accepts (ai_Unk483a60, byte -> shape: any include from ai.h flips
it, a VC6 declaration-set tie-break that blocked ai.h from including any header), so the escape hatch needs
to be narrow:
- `dcp accept ADDR --to shape|draft --why TEXT`: lowers that one function's baseline entry, records the
  reason (and the commit) next to it in the ledger; M1 then holds it at the accepted grade.
- `dcp promote` raises entries only; a fall it finds that no `dcp accept` covers is refused (listed, nothing
  written) unless `--accept-falls` is given.
- dcp-match-base skill (user decision: a judgement call, no narrow rule): the rule "never accept a regression"
  becomes the worker's judgement: a byte or shape fall is accepted when the change brings the code base as a
  whole closer to the original (truer types, fewer views / casts / duplicated records, includable headers)
  and the match it costs is no evidence of the original's source (a declaration-set tie-break is the typical
  case); a fall from a wrong change is not. Each accepted fall goes through `dcp accept` with its reason.
Built after the current gildegold header pass (it promotes by hand, checking the falls against the ones it accepted).

Done (2026-10-30): `dcp accept ADDR|NAME --to shape|draft [--readability draft] --why TEXT` (cli_match.py) lowers
the one entry to the function's current grade and fills the eighth column of ledger/grades.tsv, `accepted`
(`byte+readable -> shape+readable at <commit>: <why>`; empty otherwise; an older 7-column file reads with empty
notes). `dcp promote` refuses a fall (listed, nothing written, exit 1) unless `--accept-falls` (each such fall
noted `promote --accept-falls`); it keeps a note while the function stays below the grade it fell from and
clears it once the function is back. `dcp session wrap` reports a refused promote and fails (its gate already
fails on any M1, so it does not happen there). The skill's section 2.6 states the goal and the criterion. With
it, four tool fixes from the header passes: `dcp why NAME` resolves names; `dcp headers conflicts` reports every
name of a multi-name extern line (and --write keeps the line's other declarators), inserts the includes before
the first statement using a duplicate when that is above head.c's last include (`--at LINE` chooses), and
warns q6 for function addresses only.

## 18. libclang as the one C front end (planned 2026-10-30, user decision: "use libclang to do all the source parsing")

The sources are read by about a dozen hand-written parsers (srcscan's regex tokenizer and declaration scanner,
lint's declaration parser, the scanners of headers / datafix / edit / grade / draft / vc6.declaring_header), and
clang ran as a subprocess whose text diagnostics were regex-scraped. The goal: one front end (source/cparse.py)
that parses each unit the way VC6 sees it, every reader and editor taking facts and exact extents from it. In
stages, each with gildegold as the check (old output against new):
- stage 0 (done): libclang parses every gildegold unit with the lint flags; the diagnostics equal clang.exe's.
- stage 1 (done): lint and `dcp headers conflicts` on libclang.
- stage 2: the readers (srcscan, lint's declaration scan, grade's readability, headers' scans, the VC98 index)
  from one per-unit model, diffed against the regex scan by tools/scandiff.py before the regex code goes.
- stage 3: the editors (data fix, rename, the declaration-block edits, set_level, unit join) from the model's
  extents.
tree-sitter was weighed and not taken: it would be a second front end that guesses what clang knows (no types,
no macros: `WINAPI`, `__declspec`, `T * x;`); its niches (comments, `#define` bodies, dead branches, a file
alone) libclang covers (the text between tokens, the preprocessing record, lexing a skipped range, the unit as
context). It comes back only if parse cost breaks the edit loop, and only for lexical facts.

Done, stage 1 (2026-10-30):
- libclang (user decision: the LLVM installation's, not the PyPI wheel: libclang 23 parses a gildegold unit about
  2.3x faster than the wheel's 18; the `clang` bindings package is the dependency): `[lint] libclang = ...`,
  else beside `clang` on PATH, else the LLVM default path; `[lint] clang` is gone. Its version is part of every
  lint cache key.
- cparse.diagnostics: the lint-style list, with `name` (the identifier clang quotes, else the cursor's or token's
  at the location): calls through a function pointer, `?` before, now named (5 gildegold M7 lines). The message
  stays the only source of a diagnostic's arguments (a call written through a macro: the cursor at its location
  is the expansion, which may hold several calls). `#line` is applied by cparse from the text (line_map), not
  taken from clang, whose precompiled preamble drops the `#line` directives it holds.
- lint.call_of: one definition of an M7 call (-Wdeprecated-non-prototype also stands at a K&R declaration), for
  lint and headers alike.
- Speed (user decision: worker processes for parses in bulk): libclang in threads of one process does not scale
  (93 units in 2.4 s on 12 threads, against 1.2 s for parallel clang.exe), so cparse.many sends several parses
  to a process pool that lives as long as the process (warm in the daemon); a single unit to keep (an edit's
  unit) is parsed in process and kept live (the last 4), its next parse a reparse over its preamble (a small unit
  in ~10 ms; a large one still parses its own code: gildegold's he, 19 000 lines, ~0.13 s).
- Found on the way: the all-declarations unit's text depended on the hash seed (its pop_macro order came from a
  set), so its cache never hit and clang ran on it on every lint; now in place order. line_map counted lines
  quadratically (8 s on the 22 000 `#line` directives of alldecls).
- gildegold: `dcp lint` equal to the clang.exe run but for the 5 named pointer calls (m6=0 m5=0 m7=4710);
  `dcp headers conflicts ls cm.h ai_types.h` and `he d3.h am.h` equal. Lint (no daemon): cold 8.8 -> 6.4..8.2 s,
  warm 5.4 -> 4.5 s, after a one-line edit of he (compile included) 10.8 -> 10.5 s.

Done, stage 2a (2026-10-30; user decisions: the comments stay a per-file lexical layer, since the amalgamations
are made of what the address comments say and must exist before any parse; a header is scanned as the first
unit that includes it sees it):
- srcscan: function definitions and file-scope data declarations from cparse.model over one translation unit per
  unit (every target's fragments; models() keyed by the members' content hashes, kept in build/cache/cparse/ while
  every file the parse read is unchanged; a parse that missed an include is never kept); the address comment of a
  data statement found by its extent as before. A `#line` pin inside a part (a declared original file name) maps
  nothing: the scan maps lines by the parts it composed. tools/scandiff.py diffs it against the regex scan.
- gildegold (scandiff, every difference read): 41 functions and 22 data `static` through zlib's `local` macro;
  declarations in dead branches gone (zlib's trees/head.c GEN_TREES_H block with 4 addresses, unzip's
  NO_ERRNO_H errno, sv_MenuOpen / ai_TimeHour behind the view headers' guards), deflate.h's live branch's lines;
  `int snd_W2 = -1, snd_W1 = -2, ..;` is eight declarators (the regex saw one), so its one-address comment
  assigns none; two regex misreadings (Z_OK) gone. `dcp check` and `dcp conflicts` unchanged; the byte map loses
  the declared names at 0x5ec500.. (static_ltree, static_dtree, base_length, base_dist) and 0x5f3108 (snd_W2):
  their address comments belong on the live definitions (include/trees.h) and one address per declarator.
- Found on the way: `dcp unit join` left the second line of the joined unit's header comment in head.c (its drop
  test compared a stripped line with an indented prefix); the regex scan read past the stray text, clang does not.
- Speed (gildegold): a scan after a one-fragment edit 0.11 -> 0.20 s (the unit reparsed live), a warm scan in a
  new process 0.08 -> 0.32 s, cold 2.4 -> 5.9 s (once).

Done, stage 2b (2026-10-30; user decision: a `#define` body has no syntax tree, so the view and cast patterns
stay checks over the body text, read for the macros the preprocessor defined):
- cparse.model also lists per file the live macros (MACRO_DEFINITION, function-like or not) and the integer
  literals cast to a pointer type in code: a literal after a parenthesis is a candidate, the cursor at the `)`
  before it decides (a C-style cast to a pointer type, a typedef'd one too; casts without a pointer stepped
  over); no walk of the whole tree (1 s for gildegold's he alone). Offsets are mapped by the file's own lines:
  a location clang gives for an offset inside a macro argument reads back as the macro call's.
- srcscan: scan.macros, the views and raw object macros (L15, Q4) and the casts in `#define` bodies (A1) from
  the live `#define`s only; the code casts from the model.
- gildegold (scandiff): views and raw object macros equal; 24 macros of dead branches gone (zlib's debug
  macros); casts: one inside zlib's non-debug `Assert` (expands to nothing) gone, 9 through a typedef'd pointer
  type new (`(voidpf)0`, `(LPCSTR)0x65`: none inside the image, A1 unchanged). `dcp check` / `conflicts` equal
  to 2a's.

Done, stage 2c lint (2026-10-30): the all-declarations unit's declarations from the front end.
- cparse.model also lists per file every file-scope function declaration / definition and data declarator
  (start, name position, end, body start, kind, initialised, a definition's parameters with their default
  promotion from the canonical type), the typedefs and defined tags, and the skipped ranges
  (clang_getSkippedRanges). lint.file_scope_decls cuts each declaration's text from the file by those
  positions; the statement end and the declarator commas are read from the text (an extent ending in a macro
  call, `int f OF((int a));`, reads back as the call's start); K&R is the syntax (parameter declarations before
  the body: a prototype in scope gives the definition a prototyped type); a declaration whose spelled name is not
  the declared one (a rename macro) is left out, as _unrenamed did. _provides: the typedefs, tags and live macros
  of the model; the words of the live, non-directive lines.
- gildegold: the declarations differ only where the regex was wrong (zlib's `local` statics left out, declarations
  of dead branches gone, `return Z_OK;` no longer an extern, `__declspec(dllimport)` prototypes, arrays of
  function pointers and one K&R definition now seen). M5 finds one new conflict the regex never saw:
  src/hmt/head.c:24 declares GetModuleFileNameA with `void *hModule` against the SDK's HMODULE (the unit leaves
  windows.h out on purpose: an `@vc6 why` there, or the SDK's spelling). Lint warm 4.5 -> 2.9 s.

Done, stage 2c readability (2026-10-30): Q1..Q7 read the function's text within the front end's extent of its
definition (Scan.models: the model behind the scan) instead of the regex definitions and a brace counter
(brace_end gone). gildegold: every function's readability and failing Q rules equal (4759).

Done, stage 2c headers (2026-10-30): `dcp headers conflicts` reads the declared names (lint.file_scope_decls with
the file's model; the extra extern-line regex that caught the old parser's misses is gone), the first use of a
header's name (include_pos) and the call sites over the live code (srcscan.live_code: directives and the
preprocessor's skipped ranges blanked) of the files as they are on disk (srcscan.model_of: the scan's model,
its tree digest once per file epoch, fsmemo.epoch); a text not written yet (a trial) is read by the regex scan
until stage 3. The argument classes of a call (an integer / float / string constant) stay lexical. gildegold:
output equal on ls / he but the declaration-set counts (769 -> 771, 507 -> 564: the declarations the regex
missed); 8.8 -> 8.5 s.

Done, stage 2c system headers (2026-10-30): vc6.declaring_header indexes the C-calling-convention functions of
VC98/Include as a C compile sees them (cparse.function_headers: one translation unit including every header in
the order of preference, clang_getFunctionTypeCallingConv); the regex took declarations of dead branches too:
math.h's float / long double variants of other platforms, crtdbg.h's _DEBUG-only functions, C++-only ones (226
of 1062 names), and gave a name to a later header than an earlier one that declares it (_wchdir: wchar.h).
draft.header_declaring: the declarations of the header's model. gildegold: `dcp draft --show` equal on three
functions. Stage 2 is complete; the regex definitions / data scan (Source.definitions, Source.data,
blank_alternatives, lint._file_scope_decls_regex) stays for the texts not on disk (`headers` trials, the
editors' texts) and tools/scandiff.py until stage 3 moves the editors.

Done, stage 3 data fix (2026-10-30): datafix.declarator takes the name's position and the statement's declarator
count from the front end's model (the regex took the first whole-word match), D5 chooses `= 0` / `= {0}` by
the declarator's type (cparse.model: aggregate = an array, struct or union by the canonical type; unknown when
the declaration has an error: clang's recovery makes an unknown type name int), and D4's "defined between"
reads the models' macros, typedefs, tags, enum constants and declarations by line (defined_between; the seven
regexes of defined_in only for a file without a model). The statement's block, dimensions and splices stay
text (the edits are text). gildegold: no open D1 / D4 / D5; over all 6948 data declarators the positions equal,
one declarator the regex did not find, 154 typedef'd pointers / handles / enums now `= 0` (the word list gave
`= {0}`).

Done, stage 3 rename (2026-10-30; user decision: symbol-exact, words elsewhere): `dcp rename` of a name with an
address leaves alone the occurrences clang finds referring to a declaration not at file scope (a local, a
parameter, a struct field, a label: cparse.refs, the cursor at each word occurrence; srcscan.local_refs over every
unit whose files or headers hold the name, srcscan.unit_members / compose_unit being the scan's own units);
comments, dead branches and macro bodies follow by word as before; a name without an address (a type, a field)
is renamed by its words. The collision check: a new name that is only a local, a parameter or a field elsewhere
is no collision. gildegold (in memory, nothing written): ai_ShotHitsGround / ai_Chars / d3_Time rename as before
(7 / 918 / 175), `count` 883 -> 375 (its locals and fields kept); local_refs about 1.5 s per name. The comment and
directive edits (set_level's tags, unit join's line merge and guards, the declaration blocks) stay lexical (user
decision).

Done, stage 3 closed (2026-10-30): the regex C scanner is gone (Source.definitions / data, blank_alternatives,
lint's regex file_scope_decls, _unrenamed, file_scope_prototypes, the extern-line regex of headers, the regex
branches of the scan, the casts, the views, the macros and _provides; tools/scandiff.py, whose job it was). Every
reader takes a model: a project file the scan's, a text that is none (a test's, one line) parsed alone
(srcscan.model_alone). What stays lexical, by decision: the comments (address comments, tags, descriptions,
exemptions), the directives (#include lines, @private, the guards), the declaration blocks and their
declared_in, set_level's tags, unit join's line merge, the argument classes of `headers`, the view and cast
patterns over a `#define` body. gildegold: lint, check and conflicts equal to the commit before.

Fixed after stage 3 (2026-10-30, found by the gildegold fixes): since the lint step of stage 2c, cparse.model
dropped a function definition whose extent ends in another file, so gildegold's inftrees/f_465b00.c (the end of
inflate_trees_dynamic's body sits at the top of the next fragment, f_465c90.c) "defined 0 functions", and M.gen /
M1 followed. The definition now stays its head's file's (its end None: readability reads to the fragment's end)
and the spill is its own L.src error naming where the body ends. cparse is a helper of L.src now: a change of the
front end reruns the loader (a change of what the scan sees reached the dependent rules' stored results only
through a forced run).

## 19. One file per unit (planned 2026-10-30, user decision: "the amalgamation structure is not a good idea anymore")

The decision of 2026-10-29 (one file per function, compiled through a generated per-unit amalgamation) was taken
for merge-free parallel work (section 4). It does not buy that: the merge conflicts of `rea` came from
project-wide renames in hub files (names.log's job), and two workers inside one unit interfere in the bytes even
when git merges cleanly (literal pooling, static data order, a callee defined above its caller, D4). What it
costs: build/amalg.py's composition and `#line` segments, the `order` files and L12, the head / tail / u_ split,
L11 (file name against address), the spills of srcscan and cparse, the virtual compositions of datafix and
headers, 4668 files in gildegold. The unit is the unit of work and of ownership (one worker per unit).

The model:
- `src/<unit>.c` is the translation unit; its text order is the TU order. The head region is everything before
  the first function definition (the includes, the dcp declaration block). Notes: `notes/units/<unit>.md`.
- A function's address comment is the own-line comment directly above its definition (`/* unlinked, what */`
  for a function the binary does not hold); data comments stay trailing.
- `__FILE__`: the unit carries its `#line 1 "<original path>"` and its `#line N` pins itself; diagnostics map
  back through the file's own directives; the `file` declaration checks the image and the directive.
- Targets: every target's cflags define `DCP_TARGET_<name>`; a function of some targets only stands under `#if`
  on those macros; the scan parses a unit once per target; a check reports a function whose comment and guard
  disagree.

Stages, each with gildegold as the check (objects, grades, check, lint against the commit before):
- stage 1: function spans (a function's address comment to the end of its definition), under the fragment
  layout too: Q5, Q7, M5..M7, the readability memo, set_level and headers' function lookup key on the function,
  not on the file.
- stage 2: `dcp unit fold` (the old layout into one file per unit) and the switch of the scan and the build.
- stage 3: the editors on spans: draft inserts in address order, `dcp fn ADDR`, unit new / join / rename, data
  fix, headers, lint, the session's change list.
- stage 4: gildegold folded.
- stage 5: docs, skills, tests; the fold command and the composition removed.

Done, stage 1 (2026-10-30): srcscan.Function has `end_line`; `source` facts carry `comment` and `end`;
srcscan.Spans maps (file, line) to the function whose span holds it. Q5 reads the function's own address comment,
Q7 and M7 count the calls inside the span (lint's `calls` carry their lines: a stored lint without them counts as
none), M5 / M6 go to the function at the line, the readability memo keys on the span's text, set_level writes
the comment on the grade's `comment` line, headers' `fn=` comes from the spans. gildegold: lint and conflicts
equal to the commit before.

Done, stages 2 and 3 (2026-10-30; one commit: the editors cannot stay on fragments once the scan leaves them):
- build/amalg.py is gone; build/tu.py: a translation unit is src/<unit>.c as it stands (TU.functions from the
  scan, first_addr the least address, src_hash the file's, locate maps the compiler's `#line` positions back to
  the file's lines). compile.compile_flags adds the target's define (Toolchain.define_flag, VC6 `/D`).
- srcscan: one translation unit per unit file, parsed once per target with its DCP_TARGET_<name> (the default
  target's view gives everything, another target's adds the definitions only it holds); a function's address
  comment is the own-line comment directly above its definition; L11, L12, the order files, the fragment checks
  and the spills are gone; L16 (guard against comment). cparse reads physical positions (`#line` is the
  compiler's business; diagnostics take `presumed` for the generated all-declarations unit).
- D4 ranks by the unit file's lines, a header's definitions at the line that includes it (zlib's trees.h).
- The editors: draft inserts in address order (before the next function of the target, a target other than the
  default under its `#if`), the declaration block and the includes stay in the head region (edit.head_end), unit
  new / join / rename on src/<unit>.c and notes/units/<unit>.md, data fix and headers on the file's text, the
  session's change list from the address comments; `dcp fn KEY` prints one function; `dcp unit cat` is gone;
  `dcp unit fold` converts the old layout (to be removed after the migration).
- The readability memo keys on the span's text without the positions (an edit above a function moves it), and
  a file is lexed once per content: a one-function edit of gildegold's cm (15k lines) 18.3 s -> 11.6 s, the
  rest the compile and the lint of the unit (both whole-unit before as well).
- gildegold folded in a scratch clone: every unit compiles, every grade but one equal, the object code of 86
  units equal (compiler-local label numbers aside), 7 units with register / stack-slot swaps in functions that
  are no byte match (VC6 /O2 reacts to the token stream; the per-part `#line` directives are gone); the one fall
  is d3if_Prerender's readability: its undeclared call (d3fl_Prerender, M7) was reported under the original's
  file name before and reached no function, it is attributed now (M7 lines under a `#line` name: 3 -> 0).

Done, stages 4 and 5 (2026-10-30): gildegold folded (its commit 259839e: 93 units, 618 address comments moved
down to their definitions, the 8 declared file names in the units' `#line`; every unit compiles, every byte
match kept, check and lint as in the scratch clone; d3if_Prerender's readability fall accepted with its reason);
docs/layout.md, docs/match.md, README.md and the skills dcp-layout / dcp-match-base describe the unit file;
`dcp unit fold` and source/fold.py are gone (git history holds them), as is the declaration block's old heading.

## 20. The native core (planned 2026-10-31, user decisions: "we go native core. Speed is an absolute priority
here", Rust, each rule proven by a shadow run before its Python version is deleted)

Why: after the loop fixes of 2026-10-31 a build after an edit is ~2 .. 3 s on gildegold and the rule refresh is
the larger half of it (a line move: ~2.0 s, a body edit ~1.1 s). The refresh is no hotspot any more but ~15 rules of
40 .. 300 ms each plus the store's writes (the 26k source facts recorded again: ~0.28 s; the byte map ~0.1 ..
0.27 s). Making the Python cheaper gains ~1.3 .. 1.5x (measured: the store's read overhead, which a profile put at
~25 %, was ~5 % of the wall time); the goal is ~10x, so the rules, the store's hot paths and in the end the engine
move to native code.

The model:
- A Rust crate (native/dcp_core: pyo3 with the stable ABI, so any CPython from 3.9 loads it; rusqlite with its
  bundled SQLite; capstone where the comparison disassembles), built for x86_64-pc-windows-gnu (no MSVC on the
  machine: rustup's GNU toolchain). Built on first use like data/native/dcp_clang.c: `cargo build --release`
  into build/native/ of decompanion, the module named by the crate's source hash; no Python fallback.
- The SQLite store is the boundary. A native rule opens the project's store itself (WAL: a second connection
  beside Python's), reads the facts of its needed runs and records its run, with the same run key and the same
  out_hash; Python rules not ported yet read those facts as before. No fact crosses as a Python object.
- out_hash must be byte for byte Python's: canonical() is json.dumps(sort_keys, separators=(",", ":"),
  ensure_ascii), with Python's repr of floats.
- The proof per rule: shadow mode (DCP_SHADOW=<rule,..>): the engine runs the Python rule as the reference and the
  native one beside it, and a different out_hash is an error naming the first differing fact. A rule moves when
  its shadow agrees over tools/bench.py's scenarios and a forced recompute of gildegold; its Python version is
  deleted in the same commit.

Stages (each measured with tools/bench.py on gildegold, `--verify` after each):
- N0: the crate, its build, the canonical hash and record_run in Rust (every rule's record goes through it: the
  shadow compares all 56 rules' out_hash at once), the facts reader.
- N1: what every build reruns: the shared function comparison (match/compare.py, objfmt/coff.py, the image),
  M.match, M.draft, M8.reloc, G.grade (with diffclass and readability), D.data, M.data.content, M.data.site.
- N2: the line-move cascade: L.src's recording, the byte map, L9.analyzer.span, L.src.extent, L.unit.extent,
  L13, L5, M.lint, M1.
- N3: the remaining rules and the engine (scheduling, run keys, input hashes).

Done, N0 (2026-10-31): native/dcp_core (pyo3 0.30 abi3, rusqlite 0.41 with its SQLite, built with Rust 1.99 for
x86_64-pc-windows-gnu); src/decompanion/native.py builds and loads it; Store.record_run writes through it. Shadow:
canonical() equal on all 107229 stored fact values of gildegold and on the edge values (DEL is escaped, as every
character above 0x7e), out_hash equal for every rule's run over the bench scenarios S1 .. S7 and the test suite,
`--verify` ok; the Python hash is deleted. Also: StoredFact carries the fact's fields (no __getattr__ per read) and
a store keeps the merged, sorted fact list per selection of runs.
Measured: recording a line move's runs ~0.48 .. 0.57 s -> ~0.36 .. 0.40 s (L.src's 26k facts ~0.28 s -> ~0.22 s).
The lesson for N1 .. N3: a fact that is a Python object costs nearly as much to hand to Rust (seven attributes and
a dict walked through the C API) as Python's own record did; the gain comes when a rule's facts are made and
recorded natively, and when the rules that read them read the store natively too, so producers and consumers
move together.
