# Plan: crash capture for `dcp run` (`--debug`)

## Context

`dcp run` starts the program plainly. A crash leaves only an exit code (`exit=3221225477`) and `DCP_EXIT` for the
`after` steps. rea's `play.py` (`run_debugger`, `play.py:534-652`; helpers in `view.py:326-397`) ran the game under a
small Win32 debugger and wrote:
- `build/crash/<stamp>/crash.txt`:
  - the exception and the faulting instruction, with its memory operand worked out from the registers (`[ecx+0x40] = 0x00000040 (ecx=0)`);
  - registers, an EBP-chain backtrace, a "probable call chain" and a stack scan, named from the link map;
  - the loaded modules and the exe's sha256.
- `crash.dmp`, a minidump made with dbghelp.
- `build/crash/LATEST.txt`, pointing to the newest crash.

It handled exceptions like this:
- First-chance exceptions go back to the game (it may handle them). A fatal-looking one is kept in case the process
  then dies with an NTSTATUS exit code and no second-chance event.
- OutputDebugString and thread-name exceptions are ignored.

The goal is the same capability in decompanion, generic (nothing about a particular game), and better connected to
the decompilation: decompanion knows, for every function of the built exe, its unit, its source file and the
original's address. A crash should say which function crashed in all three terms, so the next step is
`dcp fn NAME` / `dcp asmdiff NAME`, not a hunt through a map file.

## Behaviour

- **CLI:** `dcp run NAME --debug [--dump full|state|normal|none]`. A profile can make it the default with
  `debug = true` / `dump = "state"` in `[[run]]`; `--no-debug` overrides that.
- **Starting the program:**
  - The program is started under the debugger (`DEBUG_ONLY_THIS_PROCESS`).
  - `_NO_DEBUG_HEAP=1` is set in the child's environment. Without it, a process started under a debugger gets the
    NT debug heap, which changes heap behaviour and can hide or move the very bug being chased.
  - The time limit and Ctrl+C keep working (the loop waits 200 ms per call and checks both).
- **Exceptions:**
  - Breakpoints and benign exceptions are continued.
  - First-chance exceptions are passed to the program. Ones with code >= 0xC0000000 are captured as "pending".
  - On a second chance, or an NTSTATUS exit with a pending capture: write the crash folder, then terminate.
- **Crash folder:** `build/crash/<run>-<YYYYmmdd-HHMMSS>/`, with `build/crash/LATEST.txt` pointing to it.
  - `crash.txt`, described below.
  - `crash.dmp`, written with `MiniDumpWriteDump`:
    - `full` is the default, as in rea: a missing page is what makes a dump useless;
    - `state` is the data segments plus the private read/write memory;
    - `none` writes no dump.
  - `launch.json`, a copy of the spec, so the run can be reproduced.
- **Output:** the closing line gains `crash=build/crash/...`, and the `after` steps get `DCP_CRASH` (the folder, or
  empty).

### crash.txt

- Header: run, variant, exe path and sha256, how long it ran, the exception code with its name (access violation,
  stack overflow, …) and first or second chance.
- **Where.** The faulting address named as `function+0xNN`, and for a function of the built exe also:

      fault: 0x0045a1c3  gfx_DrawSprite+0x23   unit=gfx  src/gfx.c:812   original=0x0045b0f0+0x23

  `src/gfx.c:812` is the line of the function's definition; the original's address lets you compare the same spot
  in `dcp disasm`. Inside a DLL, it is `module+offset`.
- For an access violation, the access (read/write/execute) and the faulting address. The instruction is decoded with
  the core's own x86 decoder (`x86.rs`, no capstone), and its memory operand worked out from the registers.
- Registers.
- **Call chain.** Every stack word inside the exe's `.text` whose bytes just below it are a call ending exactly
  there (`E8 rel32`, `FF 15`, `FF /2` …), named as above and with the called function where it is known. Under
  `/O2` (which omits the frame pointer), this is the backtrace that works. The EBP chain is printed after it,
  labelled unreliable.
- A stack scan: words that fall in a function of the exe, unvalidated, the first 24.
- The modules.

## Design

### Where it runs

Win32 requires the debugger loop to run on the thread that created the process. So it runs in the user's `dcp`
process, where `launch.py` already starts the program, not in the daemon. The daemon also serves one request at a
time, and a game session would block it.

The loop is **Rust**, in the core:
- `debug_run(spec_path, dump)` → `(exit_code, stopped, crash_dir | None)`.
- `launch.py` calls it when the spec says `debug`.
- It loads the core in the client process only then. That load is a few ms with the core already built; the daemon
  built it.
- It releases the GIL while it waits, and calls `py.check_signals()` once per poll so Ctrl+C reaches it.

### Win32 calls (new `native/dcp_core/src/debugger.rs`)

- Declared directly with `extern "system"`, as `cs.rs` already does; no new crate.
  - `CreateProcessW`, `WaitForDebugEvent`, `ContinueDebugEvent`, `TerminateProcess`, `OpenThread`
  - `Wow64GetThreadContext` (the core is 64-bit, the game 32-bit: rea's approach)
  - `ReadProcessMemory`, `CreateToolhelp32Snapshot` / `Module32FirstW` / `Module32NextW`, `CloseHandle`
- `MiniDumpWriteDump` is resolved at run time (`LoadLibraryW("dbghelp")` + `GetProcAddress`), so the GNU toolchain
  needs no import library.
- The structs (`DEBUG_EVENT`, `EXCEPTION_RECORD`, `WOW64_CONTEXT`, `MODULEENTRY32W`) are laid out as in rea's ctypes
  definitions (`play.py:286-324`).
- Everything outside the event loop is plain Rust that takes byte slices, so it can be unit-tested without a
  process: the call check below a return address, operand evaluation, report formatting.

### Naming addresses without opening the project

The client process should not open the project or run a source scan. So the daemon writes a symbol table at
prepare time, next to the spec: `build/run/<run>.symbols.tsv`, one row per public symbol of the link map:

    va  size  section  name  unit  src_line  original_va

- **Map rows:** parse the linked `.map`. The format is the one `vc6.rs` asks for with `/MAP`; port rea's
  `MAP_PUBLIC` regex. Size = the distance to the next symbol.
- **Unit / line / original address:** joined from the facts the store already has. These are the `source` facts
  (`what=func`, `symbol`, address), the units of `plan::plan` and the address comments the source scan read. The
  exact join (by symbol name, with the `_` prefix of the C name) is settled in implementation.
- **Cost:** written only when the link changed (the map's hash is stored in the file's first line), so a warm
  prepare stays at a few ms.
- **Use:** the debugger loads it once and binary-searches it by address.

### Code changes

- `run.rs`:
  - `RUN_KEYS` += `debug`, `dump`;
  - the spec gets `debug`, `dump`, `symbols`, `crash_root`;
  - `run_prepare` writes the symbol table.
- `debugger.rs` (new): the loop, the capture, the report, the dump. `lib.rs` registers `debug_run`.
- `cli_run.py`: `--debug`, `--no-debug`, `--dump`, passed to `run_prepare`, which puts them into the spec.
- `launch.py`:
  - when the spec says `debug`, `native.core().debug_run(...)` instead of `Popen`;
  - `DCP_CRASH` for the `after` steps;
  - the closing line gains `crash=`.
- `docs/run.md`: a "Crashes" section.

## Out of scope (later)

- Breakpoints, watches and traces (rea's `dbg.py`).
- Frame-dump conversion: game-specific, a project `after` step can do it with `DCP_CRASH`.
- `dcp crash` to re-read a crash folder against a newer build.
- Line numbers inside a function: they need `/Zd` and `/MAPINFO:LINES`, which change the objects. That is possible
  later as a variant with link flags, but linker flags are not configurable yet.

## Verification

- **Rust unit tests** (no process):
  - map parsing on a fixture copied from a real VC6 `.map`;
  - symbol lookup (exact, `+0xNN`, outside every function → `None`);
  - the call check below a return address for `E8`, `FF 15`, `FF D0`, `FF 50 xx`, and a non-call;
  - memory-operand evaluation;
  - report formatting from a synthetic capture.
- **Ignored test** (`#[ignore]`, needs VC6, like the other real-toolchain tests):
  - compile `int *p; int main(void){ return *p; }` with VC6 /O2 into a temp folder, link with `/MAP`, run it with
    `debug_run`;
  - check `crash.txt` names `_main`, says access violation reading `0x00000000`, and that `crash.dmp` exists;
  - a second exe that raises and handles an SEH exception itself must produce no crash folder (first chance passed
    through).
- **Manually, only in an isolated gildegold worktree** (`dcp wt new`, then dropped, with its junctions removed
  first):
  - `dcp run play --debug --seconds 20`: the game runs normally under the debugger and no false crash folder
    appears;
  - a temporary crash in the variant only, e.g. a `[[variant.unit]]` define behind which a source line writes to a
    null pointer at startup, kept out of the commit: the report names the function, its unit and source line and the
    original's address; `crash.dmp` opens in WinDbg or Visual Studio.
