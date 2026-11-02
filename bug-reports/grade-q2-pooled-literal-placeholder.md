# A pooled compiler literal (shared `0.0f`) is treated as a placeholder variable (Q2, disasm label)

- **Source:** match-base session 2026-11-02 (gildegold), worker 18
- **Severity:** minor
- **What happened:** `ai_Unk5eb788` at 0x5eb788 is the compiler's shared `0.0f` constant (457 references across many units); src/cm.c defines it as `float ai_Unk5eb788 = 0.0f;`. `dcp grade sv_UpdateBand` listed it under Q2 when the draft used the name, and `dcp disasm` labels it `<ai_Unk5eb788>`, both implying a real variable needing a name and an extern. Writing `0.0f` gave identical code (asmdiff `=` alias).
- **Expected:** for a small `.rdata` constant referenced from many units, say "pooled literal: write `0.0f`" instead of a Q2 placeholder; label it as a literal in disasm.
- **Repro:** use `ai_Unk5eb788` in sv_UpdateBand, `uv run dcp grade sv_UpdateBand`; `uv run dcp refs ai_Unk5eb788` (gildegold 92add7d).
- **Impact:** ~5 minutes (refs, cm.c definition, a failed build on an undeclared identifier).
- **Related:** asmdiff-symbols-pooled-literal-as-datum.md, grade-q2-ignores-union-alias.md
