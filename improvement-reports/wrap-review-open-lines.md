# Wrap: prompt to review `Open:` lines that mention changed addresses or symbols

- **Source:** match-base session 2026-11-02 (gildegold), worker 27
- **Area:** `dcp session wrap`
- **Problem:** gv's lead comment said "the functions from 0x4f30a0 on still read them through raw offsets", false after the session; only the worker's manual rewrite caught it. Stale `Open:` lines mislead the next worker.
- **Proposal:** the wrap lists `Open:` lines of touched units that name an address or symbol whose grade changed or that was renamed this session, as "review these lines".
- **Repro:** src/gv.c lead comment before gildegold 11201b8.
- **Cost of not having it:** small per session, compounding.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- src/unk_575860.c's lead comment `Open:` line says unk_58bbd0.h is "not included yet", but the unit already includes it (d8ce059). Left unchanged by the worker.
