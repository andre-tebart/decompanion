# M9 (string literal differs) is reported only once the rest of the code is equal

- **Source:** match-base session 2026-11-02 (gildegold), worker 52
- **Severity:** minor (let a wrong literal be committed)
- **What happened:** `"Locations\\Friedhof\\Fog"` lost its backslashes (heredoc) and became `"LocationsFriedhofFog"`. `dcp grade ai_GraveFogWindow` listed only the two push-placement `code` hunks, no M9; `dcp escalate` accepted it and it was committed. It surfaced only in ai_SeanceWindow, which had the same defect: once that function's code was equal, grade said `M9 ... our literal b'LocationsFriedhofSeance\x00' differs`. Fixed in 36d1d36.
- **Expected:** M9 reported whatever other hunks remain, and `dcp escalate` refusing while M9 is open.
- **Repro:** in a function with non-literal hunks left, change one character of a string literal; `dcp grade NAME` (gildegold, before 36d1d36).
- **Impact:** one wrong commit, a fix commit, ~5 minutes; would have stayed hidden without the twin function.
- **Related:** ../improvement-reports/lint-string-literal-bytes-vs-original.md, ../improvement-reports/skill-edit-scripts-not-heredocs.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- ai_GraveHauntContact (0x586ab0) and ai_GraveAgeContact (0x586e40) reached **shape** with the literal "Locations_Friedhof_Friedhof" (original "Locations\\Friedhof\\Friedhof"); M9 fired only once a sibling function became byte. All three uses fixed before wrap 85deceb. Want the shape check to run M9 too.
