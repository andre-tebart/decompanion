# Running a build

`dcp run NAME` builds a run profile, stages its run directory, runs the project's setup steps and starts the
program. Three tables of `decompanion.toml` describe it; each is named, and every name is checked when the project
opens (an unknown key, a missing variant or setup, a variant not for the target: an error of every command).

decompanion knows nothing about a particular game. What a run needs beyond files and flags (a compatibility layer in
the registry, an ini edit, a server to start) is a **step**: any command of the project, typically a script under
`tools/run/`.

## `[[variant]]`: build options

```toml
[[variant]]
name = "debug"
targets = ["exe"]                 # optional: the targets it is for (default: all)
cflags = []                       # optional: added to every unit
reason = "manual testing"
  [[variant.unit]]
  glob = "dd_vesa"                # a unit name pattern, or a list of them (as [[toolchain.unit]])
  cflags = ["/DREA_FIX_16BPP"]
```

A unit's variant flags are its normal flags, then the variant's `cflags`, then those of the first `[[variant.unit]]`
whose glob matches. Only the units a variant adds flags to are compiled; every other unit links the main build's
object. The variant's objects go into the shared object store (`build/obj/<sha256>.obj`), its rows into
`build/variant/<target>/<variant>.json`, its link into `build/link/<target>/<variant>/`. The store's `tu` table, the
rules and the grades never see a variant: the matching build stays as it is.

`dcp build --variant NAME` builds the main build, then the variant (compile and link).

## `[[setup]]`: the run directory

```toml
[[setup]]
name = "game"
dir = "build/run/game"            # default build/run/<name>
exe = "GildeGold.exe"             # the program's file name in dir (default: the linked file's)
  [[setup.stage]]
  from = "{target.dir}"           # {target.dir}: the original's folder; {root}, {toolchain.root} too
  link = ["*/"]                   # folders: a junction each (made again when it points elsewhere)
  copy = ["*.ini", "*.dll"]       # files: copied once, when missing (a step may edit the copy)
  [[setup.step]]
  run = ["python", "tools/run/compat_shim.py"]
  [[setup.after]]                 # optional: after the program exited
  run = ["python", "tools/run/collect.py"]
```

Patterns match the names at the top level of `from`, case-insensitively; a trailing `/` matches only folders. A
file is never linked (a step editing it would edit the original): a file of `link` is copied as `copy`'s are. A
real folder in the way of a junction is an error, never removed. The run directory may not lie inside `from`.
The built program is copied into the directory when its bytes changed. Its path stays the same, so a path-keyed
setting (a compatibility layer) stays valid.

## `[[run]]`: a profile

```toml
[[run]]
name = "play"
target = "exe"                    # default: the first target
variant = "debug"                 # optional: without, the main build's link
setup = "game"
args = ["DIRECTWINDOW"]
env = { REA_START = "new" }
seconds = 0                       # terminate after this many seconds (0: never)
debug = false                     # run under the debugger (see Crashes)
dump = "full"                     # the minidump of a crash: full | state | normal | none
```

## `dcp run`

    dcp run                 the profiles (as --list)
    dcp run NAME [--no-build] [--seconds N] [--prepare-only] [--debug | --no-debug] [--dump MODE] [-- ARGS...]

1. Build: the main build of the profile's target, then the variant's (or the main link).
   `--no-build` takes the last linked program.
2. Stage the setup's directory, copy the program in, and write the launch spec `build/run/<NAME>.json`.
   `--prepare-only` stops here and prints `spec=<path>`.
3. Run each `step` in the project root; a step that fails stops the run.
4. Start the program in the run directory with the profile's args (and the extra ARGS) and env. Wait for it,
   up to `seconds`; Ctrl+C terminates it.
5. Run each `after` step, then print `run=NAME exit=CODE ms=N`.

Steps 1–2 run in the daemon (the core's `run.rs`). Steps 3–5 run in the process you typed `dcp` in
(`launch.rs`, in the client), because the daemon has no window to start a program in.

Every step gets these environment variables:

| variable | value |
|---|---|
| `DCP_ROOT` | the project root |
| `DCP_TARGET`, `DCP_VARIANT`, `DCP_RUN`, `DCP_SETUP` | the names (`DCP_VARIANT` empty without one) |
| `DCP_RUN_DIR` | the run directory |
| `DCP_EXE` | the program in it |
| `DCP_ORIGINAL` | the original binary (`[[target]] path`) |
| `DCP_MAP` | the linked program's `.map` |
| `DCP_EXIT` | `after` steps only: the program's exit code |
| `DCP_CRASH` | `after` steps only: the crash folder (empty without a crash) |

## Crashes

`dcp run NAME --debug` (or `debug = true` in the profile) starts the program under a minimal Win32 debugger
(the core's `debugger.rs`), in the process you typed `dcp` in. The program gets `_NO_DEBUG_HEAP=1`: a process
started under a debugger otherwise gets the NT debug heap, which changes heap behaviour and can hide the bug.

- Exceptions the program handles itself (first chance) go back to it and leave no report.
- A crash is a second-chance exception, or an NTSTATUS exit after a fatal first-chance one. It writes
  `build/crash/<run>-<YYYYmmdd-HHMMSS>/` and points `build/crash/LATEST.txt` at it. The folder holds:
  - `crash.txt`: the report.
  - `crash.dmp`: a minidump, unless `--dump none`. `full` (all memory) is the default; `state` holds the data
    segments and private read/write pages; `normal` holds the stacks only. Open it in WinDbg (`.effmach x86`) or
    Visual Studio.
  - `launch.json`: the spec of the run.
- The closing line gains `crash=build/crash/...` and `dcp run` exits 1.

`crash.txt` holds:
- **The exception** and **the fault**. An address of the exe is named with its function, unit, definition line and
  the original's address:

      fault: 0x0040100a  deref+0xa   unit=crash  src/crash.c:2  original=0x00401234+0xa

  So `dcp fn deref` / `dcp asmdiff deref` are the next step.
- For an access violation, the access and the address.
- The faulting instruction, with its memory operand worked out from the registers:
  `mov eax, dword ptr [ecx + eax*4]   [ecx + eax*4] = 0x00000040  (eax=0x00000010, ecx=0x00000000)`.
- The registers.
- **The call chain**: the stack words that follow a call instruction, innermost first. `/O2` omits the frame
  pointer, so this is the backtrace that works; the EBP chain follows it, marked unreliable.
- A stack scan and the modules.

The names come from `build/run/<NAME>.symbols.tsv`. The daemon writes it at prepare time (when the map or the
sources changed) from:
- the link map's publics and statics;
- the unit of each object, by its content hash (the main build's rows, the variant's rows);
- the definition line and original address of each function (the source scan).
