# decompanion: the core and its seams

Every computation is the native core's (`native/dcp_core`, Rust, loaded by `native.py` as `decompanion._core`).
Python is the frontend: argument parsing (`cli*.py`), the daemon / client transport (`daemon.py`, `client.py`),
printing what the core returns, and locating the external libraries the core loads (capstone through its Python
package, libclang through the LLVM installation). A command is: parse the arguments, refresh the rules (the core's
engine), one core call, print its lines.

The rules and the ledger are generic. Everything that depends on the container, the object format, the toolchain,
the instruction set or the third-party analyzer lives behind one of five seams. VC6 / PE32 / COFF / x86-32 are the
only implementations of the first four so far; the analyzers are Ghidra and none.

## The five seams

| seam | in the core | selected by | implementation |
|---|---|---|---|
| Image | `pe.rs` (`Image`), `pyimage.rs` (its Python face) | `[[target]] image =` (default: the only format; `dcp init` opens the binary with it) | PE32 |
| ObjectFormat | `coff.rs` (`Obj`, `FunctionCode`, archives) | the toolchain | COFF |
| Toolchain | `toolchain.rs` (trait `Toolchain`), `vc6.rs` (the tools) | `[toolchain] plugin =` (default: the only one) | `vc6` |
| Isa | `cs.rs` (capstone's C API), `x86.rs` (decoder, listing, explanations) | `[[target]] isa =` (default: the image's machine type) | x86 |
| Analyzer | `analyzers.rs`, `dialect.rs` | `[analyzer] plugin =` (default: `ghidra`; `dcp init` writes the installation it finds, else `none`) | `ghidra`, `none` |

The selection and the core's source hash are the input `plugins` of every rule run (next to the image), so a
change of the core reruns every rule. The analyzer is no input of any rule: no rule runs the tool. `dcp setup` runs
its export (`analyzers.rs`) and stores the entries as blobs of kind `drafts`; the rules read them through the input
`drafts`.

### Image (pe.rs)

- sections (`va`, `vsize`, `raw_off`, `raw_size`, `chars`; `code`, `executable`, `holds_code`, `end`), `base`,
  `end`, `entry`, `is_dll`, `machine`, `timestamp`, `linker_version`, `read(va, n)`, `section_of(va)`,
  `section_data`, `cstr(va)`
- imports (DLL, name / ordinal, iat slot, hint), exports (with forwarders), relocations, the Rich entries
- the regions of its own machinery as (what, lo, hi) in the format's vocabulary (`pe.header`, `pe.rich`,
  `pe.reloc`, `pe.iat`, ...): header, directory, import and export regions
- `default_isa` (i386 -> `x86`), `kind` (`dll`, `gui`, `console`)

### ObjectFormat (coff.rs)

- library archives: members, the first linker member's symbol table, import members; `@comp.id` tool stamps
- objects: sections (data, relocations, mask of the bytes a relocation rewrites), symbols (external, unresolved,
  dllimport, constants), `function_index`, `function_code` (a function's bytes, mask and relocations to the next
  named symbol), data symbols; relocations as absolute / relative / absolute-rva with a width and `resolve`
- the writers the link needs: alias objects (weak externals), import libraries

### Toolchain (toolchain.rs, vc6.rs)

- fill forms and `fill_origin`, `function_alignment`, import stubs (`FF 25 <slot>`, 6 bytes) and their placement
- the Rich vocabulary: `rich_product`, `rich_candidates`, `declare`, `build_name`, `archive_tools`
- the CRT entries and the user entries they call; `library_archives`, `import_library_name`, `crt_strings`
- the language beyond C a draft is spelled in: `keywords`, `default_convention`, `sized_conventions`,
  `import_header`, `standard_headers`
- the evidence of the guided decisions (the plugin never declares): `installs()` (VC6: `$VC6_ROOT`, `C:/Tools/*`,
  Program Files `Microsoft Visual Studio`, each holding `VC98/Bin/CL.EXE`), `install(root)` (the version resources
  of CL.EXE, C1.DLL, C2.DLL and LINK.EXE; the compiler build is C2's, which is what a Rich compiler entry records),
  `archive_spec(name)` (`LIBCMT` -> `{toolchain.root}/VC98/Lib/LIBCMT.LIB`), `wizard_cflags()` (`/O2 /Gy`)
- the tools (vc6.rs): CL per unit (`/c`, `/E` for the include set), LINK with a response file, LIB, their
  diagnostics; the plan of the units and their flags (plan.rs), the compile (compile.rs), the link and its classes
  (link.rs), the flag probe (probe.rs, its analysis mrules.rs)

### Isa (cs.rs, x86.rs)

- capstone through its C API, the very library the Python package loaded
- the walk's decoder (flow kinds, direct targets, memory displacements with their sizes, immediates, switch-table
  shapes, the fields a relocation may start in), the listing of the instruction diff (numbers inside the image and
  our relocated fields read `X`), the hunk explanations (`regs`, `slots`, `order`, `sib`, `fpu`), register renaming

### Analyzer (analyzers.rs, dialect.rs)

A third-party tool that reads the image and hands back opinions: function starts, names, a pseudocode body per
function. Its answers are declarations (level declared, reason `<key> analysis`), never derived or proven.

- `key`: `ghidra` | `none`: the `[analyzer] plugin` value, the `how` of its start facts, the
  `decl:analyzer:<key>:<file>` producer of L.analyzer's facts, the origin `analyzer` of its names
- `available()`: Ghidra looks for its installation and the JDK (`[analyzer] root` / `java_home`,
  `$GHIDRA_INSTALL_DIR` / `$JAVA_HOME`, the newest `C:/Tools/ghidra_*` / JDK 21); none is always there
- the export: `analyzeHeadless` with the post-script `data/ghidra/DcpExport.java` (embedded in the core and written
  beside the project; its hash is part of the export key), the language from the instruction set, project and log
  in `build/ghidra/<target>/`; the entries replace the store's drafts when the export key sha256(key, image,
  script, our starts) differs from the store's meta `drafts.export` (or `--analyzer-force`); a start the last
  export was seeded with that is no longer ours makes the export fresh
- the dialect `dcp draft` reads (dialect.rs): the placeholder names the ledger never adopts (`FUN_` / `LAB_` /
  `DAT_` / `PTR_` ... + hex), the rewrite of its labels to our names, the C type of a data label, its types header
  (`data/dcp_ghidra.h`)

## Where things live in the core

- the configuration, the targets, the declarations' reading and the input hashes: project.rs; the toml line editor
  that writes declarations: tomledit.rs; `dcp init`, `target add`, `skills install`: init.rs
- the store (schema, connection, facts, runs, blobs, the byte map): store.rs, pystore.rs; the file memo: fsmemo.rs
- the engine (order, run keys, waiting, the output checks): engine.rs; the registry of every rule with its needs,
  outputs, inputs, ceiling and criterion: registry.rs; the rules: rules.rs, setup.rs, walk.rs, crt.rs, layout.rs,
  decl.rs (the `.dcl` grammar and L.decl), mrules.rs, grade.rs, readability.rs
- the C front end: clang.rs (libclang in process), frontend.rs (the scan of a tree, memoised per file content),
  srcscan.rs (one file's scan); lint: lint.rs, lintrun.rs
- the source tools: draft.rs, edit.rs, units.rs, rename.rs, datafix.rs, headers.rs, names.rs
- the read side and the commands' bodies: cliread.rs (disasm, dump, refs, layout literals / fptrs / starts),
  clicmd.rs (report, why, facts, conflicts, rules, map, build, check, fn, target list, decl add, layout next /
  units / propose, the session gate), matchcmd.rs (grade, next, asmdiff, diffclass, promote, accept, link, probe,
  lint), asmcmd.rs, compare.rs, diffclass.rs, difflib.rs, queues.rs (queues, shards, baseline, level ladder),
  layoutview.rs, decide.rs (the obligations, `dcp status`, the declarations), session.rs, libcand.rs, wt.rs

Tests of the core's code are Rust's (`cargo test`, a run fails past 2 s: a watchdog in lib.rs, DCP_TEST_BUDGET_MS);
the Python tests drive the CLI (`tests/`, the default run in-memory and under 2 s, `-m e2e` for the commands on
the synthetic dll and the installed binaries).

## The obligation model (milestone 6: guided decisions)

decompanion guides the user through every decision of the decompilation and takes none of them. `dcp init`
declares nothing: it writes the `[[target]]` with what the file gives (name, path, sha256, image format, ISA) and
the `[analyzer]` table with the plugin this machine has (ghidra when found, else none), unconfirmed. Every human
decision is an **obligation** (the core's `decide.rs`), computed on every call from the configuration and the store,
never stored:

| id | open while | evidence | resolved by | checked by |
|---|---|---|---|---|
| `toolchain.compiler` / `.linker` | no build declared, or no reason | the Rich candidates (S.rich), the PE linker version, the time stamp, the CRT strings | `dcp toolchain declare compiler= linker=` | C.toolchain (the build is a Rich candidate) |
| `toolchain.root` | no root declared, or no reason | the installs found (Toolchain.installs: versions, which declared or Rich builds each makes) | `dcp toolchain declare root=` | M.compile (warns when nothing compiles) |
| `toolchain.cflags` | no flags declared, or no reason | the wizard's flags; the probe | `dcp toolchain declare cflags=` | M.flags.proven (`dcp toolchain probe`) |
| `libs.archives` (due once the root is declared) | no archives declared, or no reason | `dcp libs candidates` (libcand.rs: every run-time archive placed on its own, cached per image and archive) | `dcp libs declare ARCHIVE...` | S.crt.code places the members, S2 / S5 count what is missing |
| `analyzer` | `[analyzer]` has no reason | the plugin, whether it is installed, the drafts | `dcp analyzer declare` | L.analyzer, L9 |
| `layout` | functions without a source, open units | the first open function | `dcp session start`, `dcp layout next` | L1..L10, L13..L16 |
| `match` | functions below byte + readable | the first item of the base queue | `dcp next` | the grades |

A declaration always carries a reason (`--why`, refused without one) and lands in decompanion.toml as `key =
value` plus `reason.<key> = "..."` in the same table (the core's `tomledit.rs`, a line editor that keeps the comments); it is
level declared, and the rules raise it. The older one-reason form `reason = "..."` still reads as the reason of
every key of its table. `dcp status` prints the phase (setup / layout / match / done), whether the gate is blocked,
then one numbered step per open obligation in order: its target, what is missing, the evidence so far, the command
that resolves it (and the commands that follow), and a `next:` line for the first step to take. `waits=` marks an
obligation that is not due until an earlier one is declared (`wait on <id>` in the view); `--json` prints the
records (`status`, `phase`, `open`; then `obligation= target= missing= evidence= resolve=`) instead.
`dcp setup`, `dcp session start` and every declaration print the status as their tail. The toolchain and libs
obligations are a gate: `dcp session start` and `dcp check` fail on them.

How a declaration feeds the rules: an external input may be absent until declared (`Project.waiting`): `libs`
waits for `libs.archives` (and for `toolchain.root` when the archives are spelled under it), `toolchain` for
`toolchain.compiler` and `toolchain.linker`. A rule reading a waiting input waits (engine.rs): its
criterion does not run, the engine records an empty run keyed by the obligations, the rules that need it run
on nothing from it, and `dcp rules` prints `waiting: <obligation>`. So setup runs in two stages around the
toolchain obligation: the first `dcp setup` runs every rule that needs no declaration (headers, sections, data
directories, imports, exports, relocations, the Rich candidates (S.rich reads `archives`, the declared archives
or none), strings, fill, the walk) and the analyzer's export, and prints the obligations; the declarations end
the waits (S.crt.code / refs / data, S4, C.toolchain, S2, M.compile, M.flags.proven), and the declare command
reruns the rules at once (the walk and everything downstream follow the placed library code). A declaration
made before the first `dcp setup` only writes (no store yet).

## What the rules may and may not know

May: facts and their vocabulary (kinds, skinds, levels), the seams' interfaces above, C-language conventions
(NUL-terminated strings, `.c` / `.cpp` / `.h` paths in `__FILE__` literals), and the walk's generic
conventions W1..W4. Docstrings may cite the VC6 / PE32 / COFF / x86 / Ghidra answers as the example of a
convention.

May not: section names, characteristic bits, file offsets beyond a Section's raw range, relocation type
numbers, COFF storage classes or symbol prefixes, byte patterns, instruction encodings or mnemonics,
mnemonic-level idioms, toolchain paths and file names, decorated entry names, address widths as literals, an
analyzer's name, its label spellings, its type names or its output format (the rules read the entries).

Kept in place on purpose: the region names (`pe.header`, ...) and the section fact's `chars`, `raw_lo`,
`raw_hi` are what the image plugin reports (fact values, unchanged); `S.strings` reads a string's bytes up
to the end of its section's raw data (a Section's own fields).

## The conventions the walk and the thunk rule rest on (VC6 / LINK / x86-32)

Walk (walk.rs, derived level):
- W1 a function's code is contiguous between its start and the next start, its jump tables follow its code;
  a direct jump crossing a start is a tail call (VC6: `pop ..; jmp f` for `return f(args)`); a table entry
  never points past the next start.
- W2 a direct call target is a function start, unless it lies inside the caller's own range (an inner label of
  assembly-written library code).
- W3 a code address in a relocated immediate field, or stored in a data section, is a function start.
- W4 a function ends at a return, an unconditional jump, and at alignment fill reached by fall-through
  (VC6 fill: `90`, `CC`, `8B FF`, `8D 49 00`); and at a known start directly after a call (the callee does not
  return: VC6 emits nothing after a call to `_exit` / `_endthread`; S.codewalk v3, milestone 3).
- Switch tables (x86.rs): `cmp r, N` ... [`mov(zx) r, byte [r + index table]`] ... `jmp dword [r*4 +
  table]`; the bound is the first `cmp reg, imm` (0 <= imm < 0x400) found scanning back at most 11 instructions,
  the index table the first byte load with a base or index register whose displacement lies in the code.

Thunk (S.thunk, derived level; toolchain.rs):
- LINK's import stub is `FF 25 <slot>` (`jmp dword ptr [slot]`), 6 bytes.
- CL emits the same bytes for `return f(...)` of a dllimport f, so the bytes are a candidate only.
- LINK places every library contribution after the objects of the command line, and packs the stubs of one
  import library back to back.
- CL starts every compiled function at a 16-byte boundary, so two compiled functions never lie 6 bytes apart.

Other VC6 facts the plugin states: the CRT start-up symbols and the user entries they call (`_DllMain@12` ->
DllMain, `_WinMain@16` -> WinMain, `_main` -> main, the wide variants), `@comp.id` = prodid << 16 | build,
`<DLL>.LIB` import libraries under `VC98/Lib`, the release wizard's flags `/O2 /Gy` (evidence for the cflags
obligation, never written).

The match phase (milestone 3; docs/match.md) adds: CL and LINK run with `VC98/Bin` and `Common/MSDev98/Bin` on
PATH, `VC98/Include` on INCLUDE and `VC98/Lib` on LIB (`[toolchain] include_dirs` / `lib_dirs` first); one CL
process per unit (`/nologo /c`); the include set from `CL /E`'s `#line` directives; a command-line warning
D4002 / D4024 or error D2016 / D2021 means a flag was refused (the probe prunes the combination); CL pads a
function's COMDAT section with fill up to the next function's alignment (M.match ends the function at its
last non-fill instruction); the switch tables of a function lie in its section; `_f` / `_f@N` / `@f@N` are
the C, stdcall and fastcall spellings of `f`; the probe grid `/O1 /O2 /Ox` x `/G3 /G4 /G5 /G6 /GB` x `/Oy /Oy-`
x `/Gy` x `/GF /Gf` x `/Ob0 /Ob1 /Ob2` with the defaults `/GB /Oy /GF /Ob1`; LINK's `.def` syntax
`LIBRARY name` / `EXPORTS f @ordinal`.
