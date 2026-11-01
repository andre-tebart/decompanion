# dcp command timings: one match-base session (gildegold, 2026-11-01)

- **Source:** a match-base session on gildegold (main checkout), base `5ecf25a`, wrap `93166f9`; 8 functions
  (6 escalated, 1 byte, 1 shape) plus one typing commit (`ls: head includes hmt.h`).
- **Method:** every `uv run dcp ...` of the session went through a wrapper that recorded the wall-clock time
  around the call (`date +%s%N` before / after, so `uv` + client start + daemon + output). Git Bash on
  Windows 11, 12 logical cores, warm daemon throughout except where noted. 234 calls.
- **Guideline it is measured against (AGENTS.md):** read commands under 10 ms warm, builds under 1 s warm.

## Summary

| | |
|---|---|
| session wall clock | 40 min (17:15:30 .. 17:55:33) |
| time inside dcp | 269.6 s (11 % of the session) |
| of that, `build` | 137.3 s (51 %), 52 calls |
| of that, `session start` | 55.0 s (20 %), one call, daemon restart |
| per-call client floor | ~0.12 s (`dcp serve --status` through `.venv/Scripts/dcp.exe`); `uv run` adds ~0.02 s |
| floor paid in total | ~33 s for 234 calls (12 % of the time inside dcp) |

No read command meets the 10 ms guideline end to end: the cheapest call costs about 120 ms before the daemon
does anything. Measured on the daemon side (total minus the floor) the cheap reads are within reach (`fn` about
5 ms), the diff tools are not (`asmdiff` about 100 ms). Warm single-unit builds take 0.9 .. 1.7 s (median
1.4 s), above the 1 s guideline, and builds after a header edit take 17 .. 18 s.

## Per command

All times in seconds, wall clock as the agent sees it.

| command | n | total | mean | median | p90 | max |
|---|---:|---:|---:|---:|---:|---:|
| build | 52 | 137.30 | 2.640 | 1.444 | 4.141 | 19.712 |
| session (start / wrap) | 4 | 59.61 | 14.903 | 1.692 | 54.967 | 54.967 |
| grade | 54 | 13.07 | 0.242 | 0.188 | 0.368 | 1.252 |
| rename | 3 | 13.03 | 4.344 | 3.947 | 6.453 | 6.453 |
| headers conflicts | 4 | 10.88 | 2.721 | 3.040 | 3.863 | 3.863 |
| check | 8 | 8.81 | 1.101 | 0.930 | 1.127 | 2.001 |
| diffclass | 34 | 7.66 | 0.225 | 0.204 | 0.272 | 0.454 |
| asmdiff | 20 | 5.29 | 0.264 | 0.246 | 0.393 | 0.509 |
| disasm | 16 | 3.54 | 0.221 | 0.214 | 0.246 | 0.296 |
| refs | 7 | 2.11 | 0.302 | 0.301 | 0.310 | 0.316 |
| fn | 11 | 1.76 | 0.160 | 0.146 | 0.172 | 0.289 |
| next | 8 | 1.72 | 0.215 | 0.216 | 0.222 | 0.241 |
| dump | 3 | 1.63 | 0.543 | 0.384 | 0.916 | 0.916 |
| why | 2 | 1.55 | 0.775 | 0.775 | 0.839 | 0.839 |
| escalate | 6 | 1.17 | 0.195 | 0.188 | 0.217 | 0.218 |
| draft --show | 1 | 0.34 | 0.339 | 0.339 | 0.339 | 0.339 |
| serve --status | 1 | 0.14 | 0.140 | 0.140 | 0.140 | 0.140 |

The only non-zero exit was `headers conflicts ls hmt.h` (rc 1 while conflicts are listed). That is the
command's contract, not a failure.

## Where a cheap call's time goes

Measured after the session, warm daemon, 3 to 5 runs each:

| call | time |
|---|---:|
| `python -c pass` (venv interpreter) | 0.065 |
| `python -c "import decompanion.client"` | 0.079 |
| `.venv/Scripts/dcp.exe serve --status` | 0.118 .. 0.128 |
| `uv run --no-sync dcp serve --status` | 0.142 .. 0.145 |
| `uv run dcp serve --status` | 0.143 .. 0.156 |
| `dcp.exe fn init_SetupNewGame` | 0.125 |
| `dcp.exe build` (nothing to compile) | 0.168 |
| `dcp.exe grade init_SetupNewGame` | 0.175 |
| `dcp.exe dump 0x6231f4 16` | 0.190 |
| `dcp.exe why 0x7603a0` | 0.206 .. 0.230 |
| `dcp.exe asmdiff init_OpenTown` | 0.224 |

That gives these daemon-side estimates (the call minus the ~0.12 s floor): `fn` ~5 ms, no-op `build`
~45 ms, `grade` ~55 ms, `dump` ~70 ms, `why` ~90 ms, `asmdiff` (a 1150-instruction function) ~100 ms.
Of the floor, the Python interpreter takes about 65 ms, importing the client 15 ms, and the console-script
launcher plus the round trip about 40 ms.

`dump` and `why` were much slower during the session (`dump` 0.38 .. 0.92 s, `why` 0.71 .. 0.84 s) than in
this warm re-measurement (0.19 / 0.21 s). Each was among the first calls of its kind in the session, so
some first-use cost seems to be paid there.

## Builds

The 52 builds in order (time of day, seconds):

```
17:18:42 1.37  17:19:28 0.92  17:19:45 0.89  17:19:46 1.31  17:22:51 4.19  17:23:23 1.02  17:23:30 0.88
17:24:43 3.88  17:25:18 1.71  17:25:36 3.63  17:25:58 1.48  17:26:10 1.02  17:26:29 1.05  17:26:59 1.24
17:27:10 1.03  17:27:26 1.46  17:31:48 2.63  17:32:43 2.63  17:33:23 1.51  17:33:35 1.05  17:34:12 19.71
17:35:07 1.50  17:35:23 1.20  17:35:32 1.20  17:39:39 1.59  17:39:55 1.54  17:40:04 1.02  17:40:14 1.06
17:40:37 3.46  17:41:12 1.47  17:41:21 1.25  17:41:29 1.04  17:41:38 1.02  17:41:53 1.43  17:44:13 17.19
17:44:52 1.65  17:45:35 1.11  17:46:09 1.52  17:46:26 1.07  17:46:38 1.52  17:46:56 1.18  17:47:05 1.08
17:47:23 1.54  17:47:33 1.07  17:47:43 0.90  17:48:27 2.69  17:52:45 5.05  17:53:53 17.94 17:54:24 4.14
17:55:01 2.22  17:55:20 0.19  17:55:32 1.83
```

- **One changed unit (the common case):** 0.88 .. 1.71 s, median about 1.2 s. The unit was usually
  `f3init` (62 functions, about 3.6 k lines) or `ls`. Some of the 2.6 .. 5 s builds recompiled two or three
  units after a shared declaration changed (4.19 s at 17:22:51: `amt.h`, `amt.c`, `f3gm.c` and `f3init.c`
  after the `amt_SendOfficeOwner` / `gm_AgeCharacter` signature fix). For the others the unit count was not
  recorded.
- **Header edits:** 29 units after adding one prototype to `f3gm.h` and the `ai_SceneChars` rename took
  17.19 s. 21 units after adding one prototype to each of three owner headers took 17.94 s. That is about
  0.6 .. 0.85 s per unit on a 12-thread machine, which suggests the unit compiles run mostly one after
  another.
- **Outlier:** 17:34:12, **19.71 s for "compiling 1 of 93 units"**. It is the first build after
  `dcp escalate init_OpenTown` (the escalate only adds an `@deep` line to the function's comment in
  `src/f3init.c`). The same kind of change (an escalate followed by a one-unit build) took 1.3 .. 1.7 s every
  other time. The cause was not found; I did not rerun it.

## Other slow spots

- **`session start`: 54.97 s.** It printed `dcp: the daemon restarts (the decompanion code changed)`. Of the
  55 s the rules took 2.9 s (`rules: 58 ran of 58, 2926 ms`); the other ~52 s are the restart and whatever
  rebuild it needs. Without the restart, `session wrap` (build, link, check, promote) took 1.3 .. 2.1 s.
- **`rename`: 2.6 / 3.9 / 6.5 s** for 1, 2 and 23 pairs touching 5, 21 and 43 reader units. Each time it
  reported that every unit kept its object, so the time goes into re-preprocessing and comparing the readers,
  not into compiling.
- **`headers conflicts --trial` / `--write`: 2.6 .. 3.9 s.** The trial compiles the unit and grades its 48
  functions, so this is in line with a one-unit build plus grading.

## Suggestions

1. **Client floor (~120 ms per call, ~12 % of the time inside dcp).** A match-base agent makes many small
   calls (`grade`, `fn`, `diffclass`, `asmdiff`). A native client (the core is Rust already), or a launcher
   that skips the Python interpreter for the common commands, would remove most of the floor. Going through
   `.venv/Scripts/dcp.exe` instead of `uv run` saves only ~20 ms.
2. **Compile the units of a header fan-out in parallel**, if that does not happen already: 21 .. 29 units
   take 17 .. 18 s on 12 threads.
3. **Investigate the 19.7 s single-unit build** after `dcp escalate` (17:34:12): no other one-unit build
   took more than 1.7 s.
4. **Report the phases of `session start` when the daemon restarts** (restart, sync / rebuild, rules), so the
   52 s outside the rules can be attributed.
5. **First-use cost of `dump` / `why`:** 0.4 .. 0.9 s at first use against 0.2 s warm. Where these load
   something on first use (the image, the ledger index), the daemon could load it at startup.
6. **Optional:** a `--time` flag (or a `ms=` field in the output) with the daemon-side duration of each
   request would make reports like this exact instead of subtracting an estimated client floor.
