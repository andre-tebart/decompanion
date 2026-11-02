# disasm / asmdiff name an `array[i-1]` access after the preceding datum

- **Source:** match-base session 2026-11-02 (gildegold), worker 19
- **Severity:** minor
- **What happened:** in sv_WeatherFrame the original's `mov edx, [eax + 0x760484]` was labelled `<sv_SeasonClimate>`; it is `sv_Weather.clouds[h-1]` (our side printed `sv_Weather-0x4`). It looked like a nonsensical read of `sv_SeasonClimate[h]`.
- **Expected:** for scaled/indexed operands whose base lies a few elements before an array the function also indexes with the same register, print `array-off` (or both names).
- **Repro:** `uv run dcp asmdiff sv_WeatherFrame --symbols` / `uv run dcp disasm sv_WeatherFrame` (gildegold 5127034).
- **Impact:** ~5 minutes.
- **Related:** asmdiff-symbols-reordered-load-marked-wrong.md, asmdiff-symbols-original-side-new-object-unresolved.md
