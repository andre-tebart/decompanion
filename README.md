# decompanion

A framework for byte-matching decompilation of VC6-era PE32 x86 binaries (exe and dll), built around a
**per-byte ledger with an evidence ladder**. For every byte of the original it answers: which section, which
symbol (function, thunk, fill, jump table, string, library data, ...), which unit and source, and **how sure
we are**.

The first attempt at this (the GildeGold.exe decomp in `../rea`) is the reference; decompanion is the refined
second iteration. Design and milestones: [docs/plan.md](docs/plan.md). Declarations and address comments:
[docs/layout.md](docs/layout.md).

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
- **Loaders** (`L.decl`, `L.src`, `L.ghidra`) are the only rules that turn typed state into facts: they emit
  `declared` facts whose producer is a file line, and refuse a missing reason. Declared facts are re-checked
  by the computed rules on every run, never trusted.
- **Targets** (`decompanion.toml [[target]]`): one project may hold several binaries of one codebase; the
  first is the default, every command takes `--target NAME`. Each target has its own **store**
  (`ledger/store.py`), `build/<target>.sqlite`, holding runs, facts, conflicts, blobs and the materialised
  byte map. A store is a cache: delete it and the next command recomputes. A worktree (`dcp wt new`) overlays
  main's store of the same target. Each target declares its own toolchain (`compiler`, `linker`, `cflags`,
  `reason`; `[toolchain]` holds the plugin, its root and defaults) and may name its own library `archives`
  (else `[libs] archives`).

## Phases

1. **setup** (`dcp setup`): headers, sections, imports, exports, base relocations, the Rich header (its
   compiler and linker candidates; the target's declaration picks one of each and `C.toolchain` checks the
   pick), library members placed by masked byte search with relocation-site coincidence (`S.crt.code`), the
   names those members' relocations prove (`S.crt.refs`: the user's `DllMain`, CRT data), import thunks
   (`S.thunk`: only where LINK's layout makes `jmp [iat]` an import-library contribution; elsewhere it is a
   compiled tail call), strings, a recursive-descent code walk with tail-call and inner-label handling
   (`rules/walk.py`), fill, and a total byte map (`S.unknown` closes it).
2. **layout** (`dcp layout ...`): declarations (`decl/*.dcl`, `ledger/decl.py`), address comments in one
   file per function (`ledger/srcscan.py`), Ghidra drafts (`dcp ghidra import`), boundary evidence
   (`L.analyze`: literal first users, fill before a start, leaked source paths), unit extents and status
   (`L.unit.extent`), and the checks L1, L3..L8, L11 (`rules/layout.py`). See [docs/layout.md](docs/layout.md).
3. **match** (next): compile, compare, grades, the match toolbox lifted from `../rea`.

## Use

```
uv sync                                   # in this repo: the venv (Python 3.15, capstone)
uv run dcp init ../guild-server "C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll"
cd ../guild-server && uv sync             # the target project depends on decompanion by path
uv run dcp setup -v                       # run every rule, print the report
uv run dcp why 0x10008cb0 --refs          # everything known about an address
uv run dcp map 0x10008c00..0x10008e00     # the byte map of a range
uv run dcp facts 0x10008cb0..0x10008d20 --kind name
uv run dcp conflicts                      # contradictions
uv run dcp check                          # the gate (every target, loaders included)
uv run dcp rules -v                       # the rule graph with criteria and timings
uv run dcp toolchain                      # per target: the declaration, the Rich candidates, C.toolchain
```

Targets:

```
uv run dcp target list
uv run dcp target add exe "C:/Program Files/GOG Galaxy/Games/The Guild Gold/GildeGold.exe"
uv run dcp --target exe setup             # or: uv run dcp setup --target exe
uv run dcp setup --all-targets            # every target in config order (also: dcp report --all-targets)
```

`dcp init` and `dcp target add` pre-fill the target's toolchain declaration from its Rich header (the compiler
entry with the most objects that no configured archive object was built with, the linker entry with the most
objects) and say so in the reason; verify it with `dcp toolchain`. A target's table, e.g. the exe linking the
DirectInput library:

```toml
[[target]]
name = "exe"
path = "C:/Program Files/GOG Galaxy/Games/The Guild Gold/GildeGold.exe"
sha256 = "d6f20fda..."
image = "pe32"
archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB", "{toolchain.root}/VC98/Lib/DINPUT.LIB"]
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2", "/Gy"]
reason = "picked at target add from the Rich header: ... (Utc12_2_C 9044 x157), ... (Linker600 8447 x53); verify"
```

Layout:

```
uv run dcp layout next [-n N] [--start ADDR]   # the first function without a fragment, with its evidence
uv run dcp layout units [-v]                   # the unit table: range, status, boundary levels, open bytes
uv run dcp layout unit propose 0x10008cb0..0x10008d20 --name dllmain --by guess --why "DllMain, Init, Exit"
                                               # runs L3/L4/L7/L8 on the proposal, writes the boundary lines
uv run dcp decl add "0x1000f3a0..0x1000f3b8 bytes dead -- unreachable epilogue copy"
uv run dcp ghidra import batch1.json ...       # saved REA batch_decompile results
uv run dcp ghidra show 0x10008d20
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
  cli.py config.py init.py disasm.py
  ledger/   fact.py store.py query.py decl.py srcscan.py ghidra.py layoutview.py
  rules/    engine.py setup.py walk.py checks.py layout.py
  repo/     wt.py                    # worktrees and seed
  image/    base.py pe32.py          # ImageFormat seam
  objfmt/   coff.py                  # COFF objects and archives
  toolchains/ base.py vc6/           # Toolchain seam: fill forms, Rich products, CRT entries
tests/                               # a synthetic PE32 dll (conftest.py); server.dll tests when it is installed
docs/                                # plan.md, layout.md
```
