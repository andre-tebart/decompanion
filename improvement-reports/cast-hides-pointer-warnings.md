# Surface pointer/integer compiler warnings instead of burying them in the gate total

- **Source:** play debugging session 2026-11-01 (gildegold)
- **Area:** dcp check / dcp build (warning reporting), draft conventions in skills
- **Problem:** the gate reports `warn=3897`, so a meaningful compiler warning cannot be told from the rest.
  An `int` passed where a pointer is expected probably raised C4047 ("differs in levels of indirection") at
  `vfs_fwrite(ai_UpdateStart, 0x18, 1, f)` (not confirmed: I didn't check the compile log). The read
  macros `LS_R` / `LS_RD` / `LS_RF` in gildegold's ls.c cast the buffer to `(int)` before passing it, so
  those sites cannot warn at all. Drafts converted from Ghidra often carry such `(int)` casts on pointers.
- **Proposal:**
  1. List compiler warnings per function in `dcp grade NAME` and keep a short, configurable set of
     warnings that fail the gate or count as grade-blocking (C4047, C4024, C4312, C4022: pointer/int and
     argument mismatches).
  2. A `dcp lint` hint for an `(int)` cast applied to an address argument of a function whose parameter
     is used as a pointer, so drafts lose these casts during match-base.
- **Repro:** gildegold commit 258ff9e, `dcp check` (warn count), `src/ls.c` lines 64 / 1403 / 2946 (the
  macros).
- **Cost of not having it:** the `ai_UpdateStart` bug went unnoticed until run time. Related:
  `address-vs-value-hunk-class.md`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- After retyping ai_GypsyHelperWindow's parameter `char *rec` -> `AIBLD *rec`, four callers (src/unk_5d33b0.c) still passed `char *`; VC6 only warns, so they were found and fixed by hand. Want `dcp grade` (or `dcp rename` / a retype) to list callers passing an incompatible pointer type.

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- `dcp build` printed only `warnings=578`; after retyping parameters (`char *` -> `AIBLD *` / `GVSEANCE *`) the new pointer-mismatch warnings at callers were invisible. Want the warnings added since the last build with file:line, or at least those in the functions just edited.
