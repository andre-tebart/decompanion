# Q6 "described" passed a function through any comment anywhere in the tree — FIXED

- **Source:** gildegold header cleanup, 2026-11-01
- **Severity:** major (grades moved by unrelated edits, in both directions)
- **What happened:** `ch_SetPos` (0x4025c0, src/ch.c) has the bare definition comment `/* 0x4025c0 */`, yet Q6
  passed: src/f3init.c carried a local copy `void ch_SetPos(...); /* 0x4025c0, ch.h */`. `dd_LockSurfaceFlags`
  passed the same way through include/d3_fl.h's `/* 0x41de30, dd_vesa.c */`. Removing such a redundant copy (header
  cleanup) dropped an unrelated function to readability=draft; adding one raised it.
- **Root cause:** srcscan collected every comment of every file whose text after the leading addresses was not
  empty, and frontend::context joined them for the whole tree. Neither who owns the comment nor what the text says
  was checked; a later address in another function's definition comment (`/* 0x4d3ac0, 0x402480 on the attacker's
  record */`) also counted for 0x402480.
- **Fix:** Q6 reads a function's own documentation only: its definition's address comment (a unit file contributes
  nothing else) and its declaration's comment in its owner header include/<unit>.h. A function's address is the
  first its comment lists per target. A text made only of file names and pointer words (`ch.h`, `as in dd_vesa.h`,
  `defined elsewhere`) describes nothing anywhere. The `headers conflicts` warning `q6` is gone (a dropped head
  duplicate can no longer carry a description).
- **Effect on gildegold:** 38 functions drop from readable to draft, all on Q6 alone (ch_SetPos, ch_SetVisible,
  ch_Create, mem_Alloc, tex_Init, ...). Readable functions: 1829 before, 1791 after.
- **Test:** `test_q6_reads_a_functions_own_documentation` (tests/test_match.py).
