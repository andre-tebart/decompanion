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
through a generated per-unit amalgamation; unit-level / pre-source declarations in **`decl/*.dcl`** files (one fact
per line, sorted by address); function and data addresses stay in the sources.

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

Source layout per unit: `src/<unit>/head.c` (includes, local types, prototypes, leading file-scope data),
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
- Walk convention W5: an unconditional jump followed only by fill up to its target is a tail call (exe without
  base relocations: zlib's `_tr_init` -> `init_block`).
- `dcp link` builds an import library a DLL lacks from the image's import directory (`make_import_library` of
  the toolchain seam; mss32.dll), import records carry their hint.

Left open, visible in `dcp check` of gildegold (the user accepted gate=FAIL for the migration commit): rea's
data debt (D5 tentative definitions 530, M9 `__FILE__` literals 125, D4 69, D1 9, M.data.content 1, data
C.overlap), one L1 where the exe walk swallows a call target, and the link's unresolved names (CRT functions
under placeholder names, an ICF-folded stub, GUID libraries not declared, two Miles stubs) that rea resolved
with hand-written alias tables.
