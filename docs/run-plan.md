# Plan: build variants, run setups and run profiles in decompanion

## Context

decompanion can compile and link a target (`dcp link` writes `build/link/<target>/GildeGold.exe`) but cannot run it. Game runs therefore still use the frozen rea repo (`uv run play` in `rea/tools/gildegold/game/play.py`). rea's AGENTS.md says it is kept "until decompanion has a run command". Running a build in rea took four things:

1. **Build options for manual testing.** rea turned extra `/D` defines on with environment variables (REA_FIX_16BPP, REA_FRAME_DUMP, REA_START), each for certain units only (`build.py:85-107`). It compiled the defines in, linked, then rebuilt the normal objects again. gildegold's sources still contain these `#ifdef`s, but nothing can turn them on.
2. **A run directory with the original game files.** rea linked every folder of the GOG install into `build/link/game` with a junction, copied the `.ini/.dll/.asi/...` files, and put the built exe next to them (`play.py:115-173`).
3. **Project-specific setup.** Two examples:
   - the HKCU `AppCompatFlags\Layers` value (`DWM8And16BitMitigation HIGHDPIAWARE`), keyed by the exe's full path. It was set by hand.
   - game.ini edits: windowed mode, no intro, no sound.
4. **Launching.** Arguments (`DIRECTWINDOW`), environment variables, working directory = run directory, and a time limit.

**Your decisions:**
- decompanion provides the *concept*: build variants, setups, run profiles, staging, hooks and launching.
- Everything game-specific (registry, ini edits, …) is a **project-defined setup step**, not decompanion code.
- v1 is a plain launch. The crash-capture debugger comes later.

## Concept: three new config tables in `decompanion.toml`

Each one is named and carries a `reason`, like the existing declarations.

```toml
# Build options: extra flags on top of the target's own build. Does not affect the matching build.
[[variant]]
name = "debug"
targets = ["exe"]                      # optional, default all
cflags = []                            # for every unit (optional)
reason = "manual testing: windowed 16bpp, frame dumps, start shortcut"
  [[variant.unit]]
  glob = "src/dd_vesa.c"
  cflags = ["/DREA_FIX_16BPP", "/DREA_FRAME_DUMP"]
  [[variant.unit]]
  glob = "src/{main,unk_575860}.c"
  cflags = ["/DREA_START"]

# How to make a run directory: which original files are needed, and the project's own setup steps.
[[setup]]
name = "game"
dir = "build/run/game"                 # default build/run/<setup name>; fixed, so path-keyed registry values stay valid
exe = "GildeGold.exe"                  # name of the built exe in the dir (default: the linked file name)
  [[setup.stage]]
  from = "{target.dir}"                # folder of the original exe ([[target]] path)
  link = ["*/"]                        # folders: junction (made again if it points elsewhere)
  copy = ["*.ini", "*.dll", "*.asi", "*.as6", "*.def", "*.sdb", "*.info"]  # files: copied once if missing
  [[setup.step]]                       # project scripts, run in order before launch; non-zero exit stops the run
  run = ["uv", "run", "python", "tools/run/compat_shim.py"]
  [[setup.step]]
  run = ["uv", "run", "python", "tools/run/game_ini.py", "--windowed", "--no-sound"]
  [[setup.after]]                      # optional, run after the process exits (e.g. undo)
  run = [...]

# Run profile = variant + setup + how to launch.
[[run]]
name = "play"
variant = "debug"                      # optional; without it, the normal build/link output
setup = "game"
args = ["DIRECTWINDOW"]
env = { REA_START = "new" }
seconds = 0                            # 0 = no time limit
```

**Information passed to hooks** (environment variables for every `step` / `after`):
- `DCP_ROOT`, `DCP_TARGET`, `DCP_VARIANT`, `DCP_RUN`, `DCP_SETUP`
- `DCP_RUN_DIR`, `DCP_EXE` (absolute path of the exe in the run dir)
- `DCP_ORIGINAL` (`[[target]] path`), `DCP_MAP` (the variant's `.map`)
- `after` hooks also get `DCP_EXIT`.

With this, the compat shim is a 10-line project script that uses `winreg` and `DCP_EXE`, and game.ini edits are another. gildegold gets them under `tools/run/`, outside decompanion.

## Implementation

### 1. Config (Rust, `native/dcp_core/src/project.rs`)
- Parse `[[variant]]`, `[[setup]]` and `[[run]]` into structs `Variant`, `Setup` (with `Stage`, `Step`) and `RunProfile`, next to `Target` (project.rs:113).
- Check keys strictly, like `TARGET_KEYS` (project.rs:27).
- Errors: unknown names, a run whose variant/setup does not exist, a variant not allowed for the target.
- Expand `{target.dir}`, `{toolchain.root}` and `{root}` with the existing `expand()` (project.rs:190).
- These tables are **not** part of the rule inputs. The "toolchain" and "targets" hashes (project.rs:443) only cover `toolchain_decl` / `targets_value`, so changing a run profile reruns no rules.

### 2. Variant build (Rust, `compile.rs`, `plan.rs`, new `variant.rs`)
- Add `plan::variant_flags(p, target, unit, variant)`: `compile_flags` (plan.rs:137), then the variant's `cflags`, then the first matching `variant.unit` cflags. Also add `/DDCP_VARIANT_<name>`, so sources can test for it, like `DCP_TARGET_<name>`.
- Split the compile loop in `compile::ensure` (compile.rs:209) into a function that takes a "row sink". Main builds keep writing the `tu` table. Variants write a new store table `variant_tu (variant, unit, src_hash, flags_hash, include_hash, obj_hash, ok, log)`.
  - Objects go to the shared content-addressed store `build/obj/<sha>.obj`.
  - The main `tu` table and the "objects" rule input are never touched. That is the problem rea had to work around by rebuilding.
- Shortcut: if a unit's variant flags equal its main flags, reuse the `tu` row's object without compiling. Only units hit by a variant glob are compiled, so a warm variant build is fast.

### 3. Variant link (Rust, `link.rs`)
- Refactor `full_link(p)` (link.rs:344) into `full_link_with(p, LinkInputs { objs, out_dir, tag })`:
  - the main path passes the objects from build facts + `tu` (today's code, link.rs:355-372) and `build/link/<target>`;
  - variants pass the `variant_tu` objects and `build/link/<target>/<variant>/`.
- The `link.json` cache (link.rs:508) stays per out_dir, so it works unchanged.

### 4. Staging (Rust, new `run.rs`)
- `stage(p, setup, exe_src) -> RunSpec`:
  1. create the dir;
  2. for each `stage`: junction folders matched by `link` (`std::os::windows::fs::symlink_dir` needs special rights, so make junctions with the `junction` crate or a small `DeviceIoControl`; no `cmd /c mklink`), and copy files matched by `copy` only if missing;
  3. copy the exe only when its hash changed.
- It never writes to the `from` folder: an error if `dir` resolves inside it.
- Returns `RunSpec { exe, dir, args, env, steps, after, seconds, hook_env }` as JSON, also written to `<dir>/launch.json`.
- Command `run_prepare_command(project, run, no_build)`: variant compile, then variant link, then stage, then the RunSpec. If the build fails, report the compile/link failure first (as in the bug report about build failures hidden behind the grade summary).

### 5. CLI and launch (Python, small)
- New `src/decompanion/cli_run.py` with `register(sub, cmd)`, like `cli_match.py`:
  - `dcp run <profile> [--no-build] [--seconds N] [--prepare-only] [-- extra args]`
  - `dcp run --list`: profiles with their variant/setup.
  - `dcp build --variant NAME`: compile + link the variant only.
- **Where it runs:** the daemon is a background process with `CREATE_NO_WINDOW` (client.py:183), so it must not start the game.
  - In `client.py`, `run` takes a special path: it sends `run <profile> --prepare-only` to the daemon via `via_daemon`, which builds, stages and prints a `spec=<path to launch.json>` line.
  - The client process then reads the spec, runs `steps` (`subprocess.run`, cwd=root, env = os.environ + hook_env), and launches the exe with `subprocess.Popen(cwd=dir)`.
  - It waits with an optional time limit (then `terminate()`); Ctrl+C terminates too.
  - Finally it runs `after` hooks and prints `run=<name> exit=<code> ms=<n>`.
- Launching in Python is fine: it is about 40 lines of process control, and all computation stays in Rust.

### 6. Docs and the project
- Add a short `docs/run.md` describing the concept and the hook environment variables.
- In gildegold (separately, after you approve): add `[[variant]] debug`, `[[setup]] game` and `[[run]] play` (plus e.g. `play-plain` without the variant), and `tools/run/compat_shim.py` + `tools/run/game_ini.py`, ported from `play.py:134-153` and the registry values in the rea notes.

## Out of scope (later)
- The crash-capture debugger (`play.py:534-652`), frame-dump/`shot` conversion and `dbg` breakpoints. `--prepare-only` + `launch.json` let a project script or a later `dcp run --debug` reuse the staging.

## Verification
- **Rust unit tests** (inline, under the 2 s budget):
  - config parsing and errors (unknown key, missing variant/setup);
  - `variant_flags` order;
  - staging in a temp dir: junction made again when it points elsewhere, copy-if-missing, exe recopied only when its hash changes, refusal when dir is inside `from`;
  - `variant_tu` keeps `tu_hash` unchanged.
- **Python unit test:** the launch/hook part of `cli_run.py` with a hand-written `launch.json`. Use `sys.executable -c ...` as both a hook and the "exe", to check the hook env vars, that a failing step stops the run, the time limit, `after` getting `DCP_EXIT`, and the exit code. This adds no new e2e tests.
- **Manually in gildegold:**
  1. `dcp build --variant debug`: then `dcp grade` still shows matching objects, and `build/link/exe/debug/GildeGold.exe` exists.
  2. `dcp run play --seconds 20`: the game starts windowed from `build/run/game`, the shim script set the Layers value for that path, and the process ends after 20 s.
  3. A warm `dcp run play --prepare-only` takes under 1 s.
