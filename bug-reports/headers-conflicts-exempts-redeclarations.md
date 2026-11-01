# `dcp headers conflicts` called a pair clean that VC6 rejects (an @original redeclaration) — FIXED

- **Source:** gildegold include driver, 2026-11-01 (on top of d495c56)
- **Severity:** major (an include written as clean, then `dcp build` failed=1)
- **What happened:** `dcp headers conflicts ahm cm.h` reported every blocker count as 0. With the include, the unit
  does not compile: src/ahm.c(27) error C2371 'util_Random': redefinition; different basic types. ahm.c declares
  `unsigned short util_Random(unsigned short n);  /* 0x42ec00, @original: ... */`; cm.h declares
  `int util_Random(unsigned short n);`. The same happened with f3gm + rt.h, ts_texture + bio.h, unk_58bbd0 + ch.h
  and f3init + ai.h.
- **Root cause:** d495c56 applied lint's exemption markers to every kind of finding, so the `supersedes` finding on
  the @original line became exempt. VC6's own C2371 at that line was also deduplicated against the exempt finding,
  and vc6 findings could be exempt too.
- **Fix:** only `call` and `other` findings can be exempt: checks at a use that VC6 compiles anyway (a call's
  arguments, an asm operand). A redeclaration with another type (`supersedes`, `clash`), an error inside a header
  and anything VC6 itself rejects (`vc6`, including the --write check) are never exempt. An exempt finding no longer
  hides a VC6 error at its line.
- **After:** `ahm cm.h` reports supersedes=1 (util_Random, exempt=-), and so do the other four pairs.
- **Test:** `test_headers_conflicts_exempt_and_shifted` has an @original `extern char width;` against the header's
  `short width`: supersedes=1, exit 1, --write refused.
