# decompanion: the plugin seams

The rules (`rules/*.py`) and the ledger (`ledger/*.py`) are generic. Everything that depends on the container,
the object format, the toolchain or the instruction set lives behind one of four seams, each a package with a
registry (`FORMATS` / `TOOLCHAINS` / `ISAS` and a `register` decorator in its `__init__.py`; the package
imports its plugins, each plugin module registers itself, so adding a plugin touches only its own package).
VC6 / PE32 / COFF / x86-32 are the only implementations so far.

## The four seams

| seam | package | selected by | implementation |
|---|---|---|---|
| Image | `image/base.py` | `[[target]] image =` (default: the only registered format; `dcp init` opens the binary with each) | `image/pe32.py` |
| ObjectFormat | `objfmt/base.py` | `Toolchain.object_format` | `objfmt/coff.py` |
| Toolchain | `toolchains/base.py` | `[toolchain] plugin =` (default: the only registered one) | `toolchains/vc6/` |
| Isa | `isa/base.py` | `[[target]] isa =` (default: `Image.default_isa`, the machine type's) | `isa/x86.py` (capstone) |

`Project.image`, `Project.objfmt`, `Project.toolchain` and `Project.isa` hand the selected plugins to the rules.
The source of every plugin package and the selection are an input of every rule run (`plugins`, next to the
image), so editing a plugin reruns the rules that read it.

### Image (image/base.py)

- `sections` (Section: `va`, `vsize`, `raw_off`, `raw_size`, `chars`; `code`, `executable`, `writable`,
  `uninitialized` from the format's characteristic bits; `holds_code` = code or executable; `end`)
- `base`, `end`, `entry`, `is_dll`, `machine`, `read(va, n)`, `read_ptr(va)`, `ptr_size`, `section_of(va)`,
  `section_data(section)`, `in_image(va)`, `cstr(va)`
- `imports()` (DLL, name / ordinal, iat slot), `exports()`, `relocations()` (absolute relocation sites), `rich()`
- `header_regions()`, `directory_regions()`, `import_regions()`, `export_regions()`: (what, lo, hi) region
  triples in the format's own vocabulary (`pe.header`, `pe.rich`, `pe.reloc`, `pe.iat`, ...)
- `default_isa`: the Isa key the machine type implies (PE32: i386 -> `x86`)

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

### Toolchain (toolchains/base.py)

- `object_format`: the ObjectFormat key of its objects
- `fill_forms`: the alignment fill byte forms; `fill_origin(run)`: names a fill run (VC6: `cc` / `nop` / `mixed`)
- `function_alignment`: the boundary every compiled function starts at
- `import_stubs(section bytes)` -> (offset, slot) candidates; `import_stub_size`; `stub_placement` (the linker's
  layout convention, prose cited by S.thunk)
- `user_entry_names()`: decorated user entry -> C name; `crt_entry_symbols()`, `crt_user_entry(symbol)`
- `archive_tools(stamps)`: tool stamps decoded to Rich (prodid, build)
- `rich_product`, `rich_candidates`, `declare`, `prefill`, `build_name`: the Rich header vocabulary
- `library_archives()`, `default_archives()`, `default_cflags()`, `import_library_name(dll)`

### Isa (isa/base.py)

- `decoder(image, lo, hi, fill_forms)` -> Decoder over a code range:
  - `decode(addr)`: Ins records in address order (memoised per rule run): `addr`, `size`, `mn`, `flow`
    (OTHER, CALL, JUMP, CJUMP, IJUMP, RET), `target` (direct), `mem` (displacements into the image with operand
    size), `imms`, `table` (the table an indirect jump reads), `fill` (one of the toolchain's fill forms)
  - `table_shape(jump, recent)` -> TableShape (`entry_size`, `bound`, `index_table`, `index_size`)
  - `field_starts(ins)`: where a relocated address field may start inside the instruction
  - `read_entry(addr, size)`: a table entry
- `ptr_size`, `byteorder`

## What the rules may and may not know

May: facts and their vocabulary (kinds, skinds, levels), the seams' interfaces above, C-language conventions
(NUL-terminated strings, `.c` / `.cpp` / `.h` paths in `__FILE__` literals), and the walk's generic
conventions W1..W4. Docstrings may cite the VC6 / PE32 / COFF / x86 answers as the example of a convention.

May not: section names, characteristic bits, file offsets beyond a Section's raw range, relocation type
numbers, COFF storage classes or symbol prefixes, byte patterns, instruction encodings or mnemonics,
mnemonic-level idioms, toolchain paths and file names, decorated entry names, address widths as literals.

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
  (VC6 fill: `90`, `CC`, `8B FF`, `8D 49 00`).
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
`<DLL>.LIB` import libraries under `VC98/Lib`, the default archive `VC98/Lib/LIBC.LIB` and flags `/O2 /Gy`.
