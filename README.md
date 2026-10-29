# decompanion

A framework for byte-matching decompilation of VC6-era PE32 x86 binaries (exe and dll), built around a
**per-byte ledger with an evidence ladder**. For every byte of the original it answers: which section, which
symbol (function, thunk, fill, jump table, string, library data, ...), which source, and **how sure we are**.

The first attempt at this (the GildeGold.exe decomp in `../rea`) is the reference; decompanion is the refined
second iteration. Design and milestones: [docs/plan.md](docs/plan.md).

## The model

- **Fact** (`ledger/fact.py`): one statement about an interval `[lo, hi)` of the image: `kind` (section,
  region, symbol, start, name, source, unit, boundary, toolchain, ref, grade, build), a `value`, a `level`,
  and `by` = the producer (`rule:S.crt.code@1`, `decl:decl/text.dcl:17`, `src:src/net/f_10001000.c:1`).
- **Levels**, combined by `min`: `proven` (forced by bytes) > `derived` (a deterministic rule resting on a
  named toolchain convention) > `declared` (a human, with a reason) > `open` (nothing known). No
  "plausible", no numbers. **Explicit or computed**: every fact is a written rule or a declaration with a
  reason, or it is open.
- **Conflicts** are records, not levels: two facts that contradict each other both stay; `dcp conflicts`
  lists them, `dcp check` fails on errors and bugs (proven vs proven = a rule is wrong).
- **Rules** (`rules/*.py`): `@rule(id, version, ceiling, needs, outputs, inputs)` on a function whose
  docstring is the exact criterion. The engine (`rules/engine.py`) memoises each run by the hash of the
  rule's code, its version, the output of every rule it needs and every external input it declares; a rule
  cannot read what it did not declare. `dcp rules -v` prints the graph with every criterion.
- **Store** (`ledger/store.py`): one SQLite file `build/dcp.sqlite` per target project, holding runs, facts,
  conflicts, blobs and the materialised byte map. It is a cache: delete it and the next command recomputes.

## Phases

1. **setup** (`dcp setup`, implemented): headers, sections, imports, exports, base relocations, the Rich
   header (compiler / linker builds, language), library members placed by masked byte search with
   relocation-site coincidence (`S.crt.code`), the names those members' relocations prove (`S.crt.refs`:
   the user's `DllMain`, CRT data), import thunks, strings, a recursive-descent code walk with tail-call and
   inner-label handling (`rules/walk.py`), fill, and a total byte map (`S.unknown` closes it).
2. **layout** (next): declarations (`decl/*.dcl`), one file per function, unit boundaries with evidence.
3. **match** (later): compile, compare, grades, the match toolbox lifted from `../rea`.

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
uv run dcp check                          # the gate
uv run dcp rules -v                       # the rule graph with criteria and timings
uv run dcp toolchain                      # the toolchain evidence
```

Output is one record per line, `key=value` tokens, addresses `0x%08x`, intervals `lo..hi` (hi exclusive).

## Repository

```
src/decompanion/
  cli.py config.py init.py disasm.py
  ledger/   fact.py store.py query.py
  rules/    engine.py setup.py walk.py checks.py
  image/    base.py pe32.py          # ImageFormat seam
  objfmt/   coff.py                  # COFF objects and archives
  toolchains/ base.py vc6/           # Toolchain seam: fill forms, Rich products, CRT entries
tests/                               # engine tests on toy rules; server.dll tests when it is installed
```
