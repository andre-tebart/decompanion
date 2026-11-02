# grade / asmdiff --symbols: print struct field names for `[reg + off]`

- **Source:** match-base session 2026-11-02 (gildegold), worker 17
- **Area:** `dcp asmdiff --symbols`, `dcp grade`
- **Problem:** the worker looked up D2VIEW, D2OBJ and D2WIN offsets with awk over d2_types.h several times per function.
- **Proposal:** when the base register's type is known (from our debug info / the source), annotate `[reg + 0x1a0]` as `D2VIEW.enabled`; at least a `dcp type D2VIEW 0x1a0` lookup.
- **Cost of not having it:** ~5 minutes per function.
- **Related:** datum-users-by-offset-and-type.md, types-duplicate-views-lint.md
