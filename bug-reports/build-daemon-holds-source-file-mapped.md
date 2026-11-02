# Writing a source file right after `dcp build` fails: "user-mapped section open"

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Severity:** minor
- **What happened:** a variant script's `[IO.File]::WriteAllText` on src/unk_575860.c failed once with "The requested operation cannot be performed on a file with a user-mapped section open", right after a `dcp build`. The daemon (or the compiler it starts) probably still had the file memory-mapped.
- **Expected:** the daemon releases source mappings when the build returns (read into memory, or close the mapping), so edits right after a build succeed.
- **Repro:** loop `dcp build` then immediately `WriteAllText` on the unit's .c (Windows), gildegold ~0891251; intermittent.
- **Impact:** one wasted variant; the failed row was easy to miss in the loop output.
- **Related:** ../improvement-reports/dcp-try-variants-in-memory.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- A Python rewrite of src/f3gm.c right after `dcp build` failed once with `OSError: [Errno 22] Invalid argument: 'src/f3gm.c'`; not repeated. Same pattern (edit, build, edit the same unit file quickly on Windows). Cost: one lost variant trial, restored from backup.
