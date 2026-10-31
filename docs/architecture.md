# decompanion: the plugin seams

The rules (`rules/*.py`) and the ledger (`ledger/*.py`) are generic. Everything that depends on the container,
the object format, the toolchain, the instruction set or the third-party analyzer lives behind one of five seams,
each a package with a registry (`FORMATS` / `TOOLCHAINS` / `ISAS` / `ANALYZERS` and a `register` decorator in its
`__init__.py`; the package imports its plugins, each plugin module registers itself, so adding a plugin touches
only its own package). VC6 / PE32 / COFF / x86-32 are the only implementations of the first four so far; the
analyzers are Ghidra and none (the core's analyzers.rs).

## The five seams

| seam | package | selected by | implementation |
|---|---|---|---|
| Image | `image/base.py` | `[[target]] image =` (default: the only registered format; `dcp init` opens the binary with each) | `image/pe32.py` |
| ObjectFormat | `objfmt/base.py` | `Toolchain.object_format` | `objfmt/coff.py` |
| Toolchain | `toolchains/base.py` | `[toolchain] plugin =` (default: the only registered one) | `toolchains/vc6/` |
| Isa | `isa/base.py` | `[[target]] isa =` (default: `Image.default_isa`, the machine type's) | `isa/x86.py` (capstone) |
| Analyzer | `analyzers/__init__.py` (the core's `analyzers.rs`) | `[analyzer] plugin =` (default: `ghidra`; `dcp init` writes the installation it finds, else `none`) | `ghidra`, `none` |

`Project.image`, `Project.objfmt`, `Project.toolchain` and `Project.isa` hand the selected plugins to the rules.
The source of every plugin package of the first four and the selection are an input of every rule run
(`plugins`, next to the image), so editing a plugin reruns the rules that read it. `Project.analyzer` is no
input of any rule: no rule runs the tool or asks the plugin. `dcp setup` runs the export (build/analyzer.py) and
stores its entries (ledger/drafts.py); the rules read the stored entries through the input `drafts`.

### Image (image/base.py)

- `sections` (Section: `va`, `vsize`, `raw_off`, `raw_size`, `chars`; `code`, `executable`, `writable`,
  `uninitialized` from the format's characteristic bits; `holds_code` = code or executable; `end`)
- `base`, `end`, `entry`, `is_dll`, `machine`, `read(va, n)`, `read_ptr(va)`, `ptr_size`, `section_of(va)`,
  `section_data(section)`, `in_image(va)`, `cstr(va)`
- `imports()` (DLL, name / ordinal, iat slot), `exports()`, `relocations()` (absolute relocation sites), `rich()`
- `header_regions()`, `directory_regions()`, `import_regions()`, `export_regions()`: (what, lo, hi) region
  triples in the format's own vocabulary (`pe.header`, `pe.rich`, `pe.reloc`, `pe.iat`, ...)
- `default_isa`: the Isa key the machine type implies (PE32: i386 -> `x86`)
- `kind`: what the start-up code calls: `dll`, `gui`, `console` (PE32: the DLL characteristic, subsystem 2 / 3)

### ObjectFormat (objfmt/base.py)

- `archive_objects(path)`: the objects of a library archive (Obj: `name`, `sections`, `code_sections`,
  `symbols`)
- Section: `data`, `size`, `relocs`, `syms`, `code`, `discard`, `mask()` (1 for every byte a relocation
  rewrites), `addend(reloc)` (what the object holds at the site)
- Reloc: `offset`, `symbol_index`, `kind` (`absolute` / `relative` / `absolute-rva` / None), `width`,
  `resolve(site_va, site_bytes, addend)` -> the address the linked site refers to
- Symbol: `name`, `value`, `section`, `defined`, `external`, `function`, `named` (external or file-static),
  `unresolved` (defined elsewhere), `dllimport` (a reference through an import slot)
- `tool_stamps(paths)`: raw tool stamp -> objects (COFF: the `@comp.id` symbol)
- Milestone 3: `read_object(path)`; Obj `functions()`, `function_code(symbol)` -> FunctionCode (`data`, `mask`,
  `relocs` as (offset, Reloc, Symbol), from the symbol to the next named symbol of its section or the section
  end), `data_symbols()` -> (symbol, `data` / `rdata` / `bss` / `common`, size); Symbol `constant` (`string` /
  `float`: a compiler literal), `common`, `imported` (the linker symbol a dllimport reference imports);
  `import_symbols(lib)`; `alias_object(path, [(alias, canonical)])` (COFF: weak externals, search alias)

### Toolchain (toolchains/base.py)

- `object_format`: the ObjectFormat key of its objects
- `fill_forms`: the alignment fill byte forms; `fill_origin(run)`: names a fill run (VC6: `cc` / `nop` / `mixed`)
- `function_alignment`: the boundary every compiled function starts at
- `import_stubs(section bytes)` -> (offset, slot) candidates; `import_stub_size`; `stub_placement` (the linker's
  layout convention, prose cited by S.thunk)
- `user_entry_names()`: decorated user entry -> C name; `crt_entry_symbols()`, `crt_user_entry(symbol)`
- `archive_tools(stamps)`: tool stamps decoded to Rich (prodid, build)
- `rich_product`, `rich_candidates`, `declare`, `build_name`: the Rich header vocabulary (nothing is picked)
- `library_archives()`, `import_library_name(dll)`
- The guided decisions (milestone 6; evidence only, the plugin never declares): `installs()` (the installations
  found on this machine: Install `root`, `versions`, `compiler_build`, `linker_build`, `ok`; VC6: `$VC6_ROOT`,
  `C:/Tools/*`, Program Files `Microsoft Visual Studio`, each holding `VC98/Bin/CL.EXE`), `install(root)` (VC6:
  the version resources of CL.EXE, C1.DLL, C2.DLL and LINK.EXE; the compiler build is C2's, the back end's,
  which is what a Rich compiler entry records: CL.EXE reports 12.00.8804 in SP5 + PP and SP6 alike),
  `crt_strings(image)` (VC6: `Microsoft Visual C++ Runtime Library`, `__MSVCRT_HEAP_SELECT`, `runtime error `),
  `library_candidates()` (VC6: LIBC, LIBCD, LIBCMT, LIBCMTD, MSVCRT(D), the C++ libraries, OLDNAMES present
  under `VC98/Lib`), `archive_spec(name)` (`LIBCMT` -> `{toolchain.root}/VC98/Lib/LIBCMT.LIB`),
  `wizard_cflags()` (VC6: `/O2 /Gy`, the release wizard's)
- Milestone 3, the tools themselves:
  - `available()`: the compiler is installed (else nothing compiles and the match rules warn)
  - `compile(src, obj, flags, include_dirs, cwd)` -> CompileResult (`ok`, `log`, `diagnostics` as Diagnostic
    file / line / severity / code / message, `refused_flags`): one compiler process for one unit (VC6:
    `CL.EXE /nologo /c <flags> /I.. /Fo<obj> <src>`)
  - `includes(src, flags, include_dirs, cwd)` -> (the files the preprocessor read, log) (VC6: `CL /E`, the `/P`
    listing on stdout, its `#line` directives; VC6 has no /showIncludes)
  - `include_search_dirs(dirs)`: every directory an include may resolve to (their listing keys the include-set
    cache); `library_search_dirs()`
  - `undecorate(symbol)` (`_f@12` -> `f`), `data_symbol(cname)` (`f` -> `_f`)
  - `link(LinkJob)` -> LinkResult (`ok`, `log`, `unresolved`, `errors`, `args`): one linker process (VC6:
    `LINK.EXE @response file`, toolchains/vc6/link.py)
  - `default_libraries(kind)`, `entry_object(kind, dir, user_entry)` (a generated stub when the sources name
    the user entry otherwise), `module_definition(name, exports)` (the .def text with ordinals)
  - `probe_grid()` -> [(group, alternatives)], `probe_defaults()` (the tie-break)
- Milestone 4, drafting: `declaring_header(name)` (the system header that declares a C library function; VC6:
  the first header of VC98/Include declaring it `__cdecl`, the C89 headers first), `import_header(dll)` (VC6:
  `windows.h` for every system DLL); the language beyond standard C that a draft is spelled in: `keywords`
  (VC6: `__cdecl __stdcall __fastcall __thiscall __int64 __declspec __asm`), `default_convention` (the
  skeleton's prototype; VC6: `__cdecl`), `sized_conventions` (the conventions whose decorated name carries the
  parameters' size, so a declaration needs the whole prototype; VC6: `__stdcall __fastcall __thiscall`)

### Isa (isa/base.py)

- `decoder(image, lo, hi, fill_forms)` -> Decoder over a code range:
  - `decode(addr)`: Ins records in address order (memoised per rule run): `addr`, `size`, `mn`, `flow`
    (OTHER, CALL, JUMP, CJUMP, IJUMP, RET), `target` (direct), `mem` (displacements into the image with operand
    size), `imms`, `table` (the table an indirect jump reads), `fill` (one of the toolchain's fill forms)
  - `table_shape(jump, recent)` -> TableShape (`entry_size`, `bound`, `index_table`, `index_size`)
  - `field_starts(ins)`: where a relocated address field may start inside the instruction
  - `read_entry(addr, size)`: a table entry
- `ptr_size`, `byteorder`
- Milestone 3, the instruction diff: `listing(code, va, mask, image_range, fill_forms)` -> [Line(addr, size,
  text, fill)] (numbers inside the image and our relocated fields read `X`); `explain(xa, xb, context)` -> the
  ISA's hunk class (`regs` / `slots` / `order` after a renaming / `sib` / `fpu`) or None; `one_renaming(a, b)`;
  `rename_registers(lines, mapping)` (x86: ported from the first attempt's diffclass onto capstone's spelling)
- Milestone 4, reading: `disasm(code, va, fill_forms)` -> [Line] in the disassembler's own text (`dcp disasm`,
  the skeleton of `dcp draft`); `numbers(text)` -> (start, end, value) of every number in such a text (where
  `dcp disasm` puts the ledger's name of an address)

### Analyzer (analyzers/base.py)

A third-party tool that reads the image and hands back opinions: function starts, names, a pseudocode body per
function. Neither a toolchain nor a language property; its answers are declarations (level declared, reason
`<key> analysis`), never derived or proven. Constructed like a Toolchain with its table (`[analyzer]`) and the
project's path expansion.

- `key`: `ghidra` | `none`: the `[analyzer] plugin` value, the `how` of its start facts, the
  `decl:analyzer:<key>:<file>` producer of L.analyzer's facts, the origin `analyzer` of its names
- `available()` -> Install (`where`, `detail`; `ok`, else `reason`): Ghidra looks for its installation and the
  JDK (`[analyzer] root` / `java_home`, `$GHIDRA_INSTALL_DIR` / `$JAVA_HOME`, the newest `C:/Tools/ghidra_*` /
  JDK 21); none is always there
- `script_hash()`: what makes the export besides the image and our starts (Ghidra: the post-script
  `data/ghidra/DcpExport.java`); part of the export key
- `export(install, image, isa_key, starts, out_dir, fresh)` -> Export: `entries` (Entry: `start`, `end`, `ranges`,
  `size`, `name`, `body` (the pseudocode), `seeded` (made at one of our starts on our request: no claim of the
  tool's), `requested`, `source`, `analyzer`), `failed` (one message per item), `digest` (the analysed binary's
  sha256), `ms`, `out`. Ghidra: `analyzeHeadless` with the
  post-script, the language from the instruction set (`LANGUAGES`: `x86` -> `x86:LE:32:default`), project and
  log in `out_dir` = `build/ghidra/<target>/`; none: nothing
- The dialect, what `dcp draft` reads (source/draft.py composes it with the toolchain's language out):
  `is_placeholder(name)` (names the ledger never adopts; Ghidra: `FUN_` / `LAB_` / `SUB_` / `DAT_` / `PTR_` /
  `thunk_FUN_` + hex), `rewrite(body, own, names, labels)` (its labels to our names: `own` = the drafted
  function's (theirs, ours), `names` = how a draft spells a function / datum at an address, `labels` = the
  tool's name -> address of every function it named), `data_labels(body)` -> {address: C type} (Ghidra: by the
  label prefix, `PTR_` `undefined *`, `s_` / `u_` `char []`, ...), `unknown_data_type` (Ghidra: `undefined4`),
  `types_header` (the shipped header of its type names; Ghidra: `data/dcp_ghidra.h`; none: None)
- `analyzers.dialect(key)`: the plugin without configuration, for reading stored entries of any analyzer
  (the core's dialect.rs, names.rs, draft.rs)

The run (`build/analyzer.py`, inside `dcp setup` after the rules): when `available()` and the export key
sha256(key, image sha256, `script_hash()`, our starts) differs from the store's meta `drafts.export` (or
`--analyzer-force`), `export` and `ledger/drafts.py replace` (the store's drafts become exactly the export's
entries: blobs of kind `drafts` keyed by image and start, meta `drafts` their hash = the input `drafts`), then
the rules again: L.analyzer (its starts) and L9 read the input, the rules that need every start (L4, L5) follow.
When a start the last export was seeded with is no longer ours (meta `drafts.starts`; the typical case is the
first `dcp setup`, which runs before the library archives are declared), the export is `fresh`: Ghidra imports
and analyses again instead of reusing its project, so no function seeded at a stale start stays in it and the
drafts do not depend on the order of the declarations (milestone 6).
Our starts are every start fact but L.analyzer's and every walked or placed function, inner labels excluded.

## The obligation model (milestone 6: guided decisions)

decompanion guides the user through every decision of the decompilation and takes none of them. `dcp init`
declares nothing: it writes the `[[target]]` with what the file gives (name, path, sha256, image format, ISA) and
the `[analyzer]` table with the plugin this machine has (ghidra when found, else none), unconfirmed. Every human
decision is an **obligation** (`obligations.py`), computed on every call from the configuration and the store,
never stored:

| id | open while | evidence | resolved by | checked by |
|---|---|---|---|---|
| `toolchain.compiler` / `.linker` | no build declared, or no reason | the Rich candidates (S.rich), the PE linker version, the time stamp, the CRT strings | `dcp toolchain declare compiler= linker=` | C.toolchain (the build is a Rich candidate) |
| `toolchain.root` | no root declared, or no reason | the installs found (Toolchain.installs: versions, which declared or Rich builds each makes) | `dcp toolchain declare root=` | M.compile (warns when nothing compiles) |
| `toolchain.cflags` | no flags declared, or no reason | the wizard's flags; the probe | `dcp toolchain declare cflags=` | M.flags.proven (`dcp toolchain probe`) |
| `libs.archives` (due once the root is declared) | no archives declared, or no reason | `dcp libs candidates` (build/libcand.py: every run-time archive placed on its own, cached per image and archive) | `dcp libs declare ARCHIVE...` | S.crt.code places the members, S2 / S5 count what is missing |
| `analyzer` | `[analyzer]` has no reason | the plugin, whether it is installed, the drafts | `dcp analyzer declare` | L.analyzer, L9 |
| `layout` | functions without a source, open units | the first open function | `dcp session start`, `dcp layout next` | L1..L10, L13..L16 |
| `match` | functions below byte + readable | the first item of the base queue | `dcp next` | the grades |

A declaration always carries a reason (`--why`, refused without one) and lands in decompanion.toml as `key =
value` plus `reason.<key> = "..."` in the same table (`tomledit.py`, a line editor that keeps the comments); it is
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
`toolchain.compiler` and `toolchain.linker`. A rule reading a waiting input waits (rules/engine.py): its
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

Walk (rules/walk.py, derived level):
- W1 a function's code is contiguous between its start and the next start, its jump tables follow its code;
  a direct jump crossing a start is a tail call (VC6: `pop ..; jmp f` for `return f(args)`); a table entry
  never points past the next start.
- W2 a direct call target is a function start, unless it lies inside the caller's own range (an inner label of
  assembly-written library code).
- W3 a code address in a relocated immediate field, or stored in a data section, is a function start.
- W4 a function ends at a return, an unconditional jump, and at alignment fill reached by fall-through
  (VC6 fill: `90`, `CC`, `8B FF`, `8D 49 00`); and at a known start directly after a call (the callee does not
  return: VC6 emits nothing after a call to `_exit` / `_endthread`; S.codewalk v3, milestone 3).
- Switch tables (isa/x86.py): `cmp r, N` ... [`mov(zx) r, byte [r + index table]`] ... `jmp dword [r*4 +
  table]`; the bound is the first `cmp reg, imm` (0 <= imm < 0x400) found scanning back at most 11 instructions,
  the index table the first byte load with a base or index register whose displacement lies in the code.

Thunk (S.thunk, derived level; toolchains/vc6):
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

Where the layout tooling lives (milestone 4): `analyzers/` (the Analyzer seam; Ghidra's post-script
`data/ghidra/DcpExport.java` and types header `data/dcp_ghidra.h` are referenced only from
`analyzers/ghidra.py`), `build/analyzer.py` (the export inside `dcp setup`), `ledger/drafts.py` (the stored
entries), `ledger/names.py` (one C name per address by a fixed order of origins),
`source/draft.py` / `source/units.py` / `source/edit.py` (the files `dcp draft`, `dcp unit new|join|rename` and
`dcp rename` write; names.log), `repo/session.py` (the session gate's record and the computed report),
`cli_read.py` / `cli_draft.py` / `cli_layout.py` / `cli_session.py` (the commands), `skills/` (the agent skills).

Where the match phase lives: `build/` (amalg, compile, link, probe: they run the tools; no rule runs a tool),
`match/` (compare, diffclass: pure functions over objects and listings), `rules/match.py` / `match_data.py` /
`grade.py` (the rules; they read objects through the store's `tu` table, input `objects`), `ledger/grades.py`
(queues, baseline, the level ladder), `source/cparse.py` (libclang: the C front end), `source/lint.py` (the declaration checker), `cli_match.py` (the commands).
