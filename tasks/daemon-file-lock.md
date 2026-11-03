# Source files locked after a build (Windows "user-mapped section")

- **Priority:** P1 (verify first) · **Size:** S to investigate, M to fix

## Problem

After a build, writing a source file fails with "the requested operation cannot be performed on a file with a
user-mapped section open".

## Root cause (likely, unconfirmed)

- dcp never maps files itself: there is no mmap in src/, and fsmemo uses `fs::read`.
- libclang is loaded in-process (clang.rs:200-214). The daemon keeps up to 4 live translation units (frontend.rs:33
  `LIVE_UNITS`, `with_parse_as` at 197-232).
- LLVM memory-maps the files it reads from disk (16 KB and larger) and holds them while the unit lives.
- The main file is passed as an unsaved buffer (clang.rs:320). Headers, and the src pieces the all-declarations lint
  unit reads (lintrun.rs:136-151), are read from disk.
- Other holders are possible: git processes, Defender. dcp's own writes already wait out errors 1224/32/33
  (edit.rs:84-104).

## Task

1. Reproduce, and confirm the holder with handle.exe or Process Explorer on the daemon pid.
2. If it is libclang: pass every project file libclang reads as an unsaved buffer from fsmemo, which already holds the
   bytes. libclang then sees exactly the bytes dcp hashed.

## Reports

- build-daemon-holds-source-file-mapped
