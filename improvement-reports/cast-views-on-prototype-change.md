# Warn when a prototype change affects `@original` cast views in other units

- **Source:** match-base session 2026-11-02 (gildegold), worker 31
- **Area:** `dcp check --strict` / lint / `dcp refs --casts`
- **Problem:** session 6c8587c had declared `gm_TitleJob` as `unsigned char` with per-unit `@original` cast macros `gm_TitleJobI` (am.c:26, main.c:21, unk_575860.c:710, unk_4a7140.c:40) because callers read an int. This session found the callee really returns int (`xor edx, edx; mov dl, [eax+edi+0x74]; mov eax, edx; ret` at 0x5044fc; caller tests eax) and changed f3gm.h / f3gm.c to `int` (commit 7adc297; gm_TitleJob 11 -> 6 differing, caller to byte). The four `gm_TitleJobI` macros were missed (search `gm_TitleJob\(` doesn't match `gm_TitleJobI(`) and are now no-op casts with stale comments ("f3gm.h: unsigned char"). Nothing surfaced the earlier decision.
- **Proposal:** when a declaration's type changes, list every `@original`/`@vc6` cast macro of that symbol in other units with its comment; flag casts that became no-ops (cast type equals the prototype) as redundant.
- **Repro:** grep `gm_TitleJobI` at gildegold 28b8643.
- **Cost of not having it:** a follow-up commit to drop the stale macros and re-grade their callers.
- **Related:** headers-signature-dry-run.md, lint-placeholder-cast-macros.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 56) - stale cast macro
- f3gm's lead comment said gm_GetWorth was float in gv.h, but gv.h already declares `int gm_GetWorth(unsigned short)`; the cast macro `I50A640 ((int (*)())gm_GetWorth)` was simply stale, found by grepping headers. Want lint / `dcp headers` to flag a unit-local cast macro whose target prototype now agrees with every header. Cost: ~2 calls.
