# Q3 reports a flag constant inside the image range as an address literal

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Severity:** minor
- **What happened:** in sv_ActivityName (0x52b3c0), `(c->flags1cc & 0x1000000) == 0` made `dcp grade sv_ActivityName` report `Q3 addresses: 0x1000000`. 0x1000000 lies in the image range (0x400000..0x14ed000) but is an `&` operand, never a pointer. The old draft had dodged the same check by writing `(unsigned)&txt_Keys + 0x181c0`, a constant spelled as a fake address, which is far worse. Workaround: `(1 << 24)`.
- **Expected:** Q3 skips operands of `&`, `|`, `^`, `~`, shifts and compares against masked values; at least, it only fires when the literal is cast to a pointer or dereferenced.
- **Repro:** the expression above, `uv run dcp grade sv_ActivityName` (gildegold 3e842a0).
- **Impact:** ~2 minutes, plus the risk that workers "fix" it by inventing fake symbol+offset addresses.
- **Related:** ../improvement-reports/lint-symbol-plus-offset-immediate.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- Q3 flagged the bit mask `0x800000` (gm_DailyCharacterStep / f3gm) as an address literal; the worker wrote it as `(1 << 23)` to silence it.

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- gm_CatchDisease (0x505230, f3gm): `(w & 0x700000) == 0` gave `Q3 addresses: 0x700000`; worker rewrote all eight masks in the family as `(7 << 20)`-style shifts. ~1 extra build/grade cycle.
