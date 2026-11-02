# Report functions placed far from their address order within a unit

- **Source:** match-base session 2026-11-02 (gildegold), worker 32
- **Area:** lint / `dcp check` / `dcp fn`
- **Problem:** `dcp fn ai_ChooseSubAction` (0x495a50) gives `at=src/am.c:10991-11049`, while its address neighbours ai_ChooseAction (0x4957d0) and ai_ExecuteAction (0x495ce0) sit at lines 3554-3617 and 3624-3673. The skill says the file holds the original TU order and a function's position affects its callers' code (same-unit callee knowledge), yet nothing flags this. Earlier sessions also hit out-of-order spots in sv.c and gv.c (see scoped-function-body-edit.md). A misplaced callee could explain leftover allocation differences in am.
- **Proposal:** a lint/check rule (or a note in `dcp fn` / `dcp grade`) for functions out of address order within a unit, distinguishing deliberate exceptions if any are recorded.
- **Repro:** `uv run dcp fn ai_ChooseSubAction` vs `uv run dcp fn ai_ChooseAction` at gildegold 16efd88.
- **Cost of not having it:** none visible yet; may hide matches.
- **Related:** scoped-function-body-edit.md, vc6-optimizer-hints.md (caller-saved register across same-unit call)
