# asmdiff --symbols leaves the original side as bare addresses inside a newly defined object

- **Source:** match-base session 2026-11-01 (gildegold), worker 12
- **Severity:** minor
- **What happened:** after settling gap blocks into sv_SkyFair and sv_Weather, `dcp asmdiff --symbols` still shows the original side as bare addresses (`+ mov edx, dword ptr [0x6238f0]`, `push 0x7605b0`), so lines get `!` or -/+ where `=` (alias) would be right.
- **Expected:** the original side resolves addresses inside a newly defined object as sym+off, like ours.
- **Repro:** after the commit "data sv_SkyFair / sv_SkyMedium from the gap block" (gildegold, before 3b912d2), `uv run dcp asmdiff sv_SetupWeather --symbols`, sky layer block 0x6238e8..0x62393c.
- **Impact:** small; confusion over whether `!` meant a wrong datum.
- **Related:** asmdiff-symbols-reordered-load-marked-wrong.md, asmdiff-symbols-pooled-literal-as-datum.md
