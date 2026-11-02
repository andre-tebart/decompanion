# `dcp refs NAME --decl-sources`: which declaration each unit actually sees

- **Source:** match-base session 2026-11-02 (gildegold), worker 25
- **Area:** `dcp refs`
- **Problem:** before deleting a declaration from a header there's no way to see which units get the symbol only from that header; `dcp refs` lists declarations but not which one is in effect at each call, nor calls preceding any prototype (implicit declarations). Deleting gv.h's duplicate prototype of 0x4c4ac0 broke f3gm.c.
- **Proposal:** per unit, the declaration in effect at each call site (header + line, local K&R, or implicit).
- **Cost of not having it:** ~5 minutes plus a revert.
- **Related:** headers-signature-dry-run.md, stale-local-prototype-flag.md
