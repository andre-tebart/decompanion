# decompanion

`dcp` is a tool for byte-matching decompilation of 32-bit x86 Windows programs built with **Visual C++ 6**: you
rewrite a program in C until the original compiler turns your sources back into the original's exact bytes, and
dcp keeps track of how far you are.

It maps every address of the original over time. At the start nothing is known; as units, functions and data are
declared, drafted and matched, more and more of the image is explained, and dcp can always say what is at an
address, which source line it comes from, and where the mapping contradicts itself. A project is done when every
function is byte-identical and the whole program links to the original image.

What it does:

- **Layout**: finds function starts, unit (translation unit) boundaries, library code (the CRT and static
  libraries placed from their archives), imports and data, from the image itself and from your declarations.
- **Drafts**: writes a first C version of a function from Ghidra's pseudocode, with the names the project
  already knows.
- **Matching**: compiles each unit with the original toolchain and grades every function (byte, shape, draft) and
  its readability; `asmdiff`, `diffclass` and `frame` show why a function differs, `try` compiles variants.
- **The gate**: `dcp check` builds, links the whole program and fails on errors and on any grade that fell below
  the baseline (`ledger/grades.tsv`); regressions you want are declared as debt.
- **Agents**: ships skills for Claude Code (`dcp skills install`) that run layout and matching sessions with it.

Every command answers from a store the project's daemon keeps current; reads take a few milliseconds.

## Requirements

- Windows (x64 host)
- **Visual C++ 6.0** with the service pack and Processor Pack your target was built with (`dcp toolchain` reads
  the target's Rich header and names the builds it needs)
- **Ghidra** 12 with JDK 21, for drafts (optional)
- **LLVM** (libclang), for `dcp lint` (optional)
- the platform SDKs your target used (DirectX and the like), as the toolchain declaration names them

## Install

With [uv](https://docs.astral.sh/uv/), from a release (no Rust needed):

```
uv tool install "decompanion @ https://github.com/andre-tebart/decompanion/releases/download/v0.1.0/decompanion-0.1.0-py3-none-win_amd64.whl"
```

or pinned per project, in the project's `pyproject.toml` (then `uv sync --group dcp` and `uv run dcp ...`):

```toml
[dependency-groups]
dcp = ["decompanion==0.1.0"]

[tool.uv.sources]
decompanion = { url = "https://github.com/andre-tebart/decompanion/releases/download/v0.1.0/decompanion-0.1.0-py3-none-win_amd64.whl" }
```

From source (Rust stable; without Visual Studio, use the GNU host: `rustup set default-host x86_64-pc-windows-gnu`):

```
cargo install --path .
dcp self install      # later: rebuild this checkout and replace the installed dcp
```

## Getting started

```
dcp init mygame "C:/Games/Game/Game.exe"   # a git repository around the binary; it declares nothing
cd mygame
dcp setup                                   # runs every rule, the analyzer's export, prints the open obligations
dcp status                                  # the next decision, with its evidence and the command that makes it
```

Every decision (compiler, linker, flags, library archives, analyzer) is an obligation `dcp status` names when it is
due, with the evidence for it; you make it with a reason:

```
dcp toolchain declare compiler="cl 12.00.9044" linker="link 6.00.8447" cflags="/O2 /Gy" root=C:/Tools/MSVC600 --why "the Rich header: ..."
dcp libs declare LIBC.LIB --why "no MSVCRT import; LIBC places 157 members"
```

Then the work is layout (`dcp layout`, `dcp unit new`, `dcp draft --next`) and matching (`dcp next`, `dcp build`,
`dcp grade`, `dcp asmdiff NAME`), with `dcp check` as the gate before each commit. `dcp <command> -h` describes
each command.

## Configuration

`decompanion.toml` in the project root:

```toml
[target]
name = "game"                      # the store's name and the ledgers' first column (default: the binary's stem)
path = "{game}/Game.exe"
sha256 = "..."                     # written by dcp init
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2", "/Gy"]
archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB"]
reason.compiler = "..."            # every declaration carries its reason

[toolchain]
root = "{msvc6}"
include_dirs = ["{dxsdk}/include"]
lib_dirs = ["{dxsdk}/lib"]

[analyzer]
root = "{ghidra}"

[paths]                            # the directories outside the project; `{name}` stands for one anywhere above
game = "C:/Games/Game"
msvc6 = "C:/Tools/MSVC600"
dxsdk = "C:/Tools/DXSDK61"
ghidra = "C:/Tools/ghidra_12.1.4_PUBLIC"
```

On another machine, `decompanion.local.toml` (not committed) gives that machine's directories:

```toml
[paths]
game = "D:/Games/Game"
msvc6 = "D:/VC6"
```

## Development

```
cargo test --release                          # the unit and command tests (a few seconds)
set DCP_VC6=C:/Tools/MSVC600 & cargo test --release -- --ignored      # also the end-to-end tests that need VC6
```

`AGENTS.md` states the design principles: one binary, every command fast, VC6 / PE / x86 solved directly.

## License

MIT, see [LICENSE](LICENSE).
