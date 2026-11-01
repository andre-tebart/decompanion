# diffclass hints for recognisable compiler idioms

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** diffclass
- **Proposals:**
  - **`?:` with two constants:** the `neg/sbb/and C/add B` idiom for `cond ? A : B` shows up as `code` hunks. A hint such as "looks like `x ? B+C : B`" would help. Cost: about 5 minutes to recognise.
  - **A char compare that can never be true:** `mov al,[..]; cmp eax,-0x21` is an `unsigned char` compared with the char constant `'\xdf'` (always false), which revealed the record pointer type. A hint such as "signedness: unsigned byte vs signed char constant" would help. Cost: about 5 minutes; very useful once understood.
- Related: vc6-optimizer-hints.md
