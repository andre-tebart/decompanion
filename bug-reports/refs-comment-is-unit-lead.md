# `dcp refs` reports the unit's lead comment as a function's `comment=`

- **Source:** match-base session 2026-11-02 (gildegold), worker 45
- **Severity:** minor (misleading; could skew Q6 judgments)
- **What happened:** for functions in src/unk_575860.c, the `definition=` line's `comment=` is the first comment of the file, not the address comment above the function: `dcp refs ai_QueryChapter3Step2` (was ai_Unk5770e0) printed `definition=src/unk_575860.c:1668 ... comment='/* unk_575860.c -- the tutorial module ("FT*" record names, ...'`. Same for 0x5771b0, 0x577320, 0x577330, 0x577450, 0x577490, 0x5774d0.
- **Expected:** the address comment directly above the definition.
- **Repro:** `uv run dcp refs ai_QueryChapter3Step2` at gildegold 6b681ee.
- **Impact:** ~1 minute; risk that an agent trusts `comment=` as the function's documentation.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- `dcp refs ai_Unk6f1bac` printed `definition=src/f3gm.c:860 ... comment='/* The game data unit (0x4f9e30 .. ...'` (the file's first comment, not line 860's address comment). Same for ai_Unk61772c and gm_CharNameRecord.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- `dcp refs unk_Unk4fbb80` (also 0x4fbe90, 0x4fc890, `gm_PlaceOnStage`) printed `definition=src/f3gm.c:1192 ... comment='/* The game data unit (0x4f9e30 .. 0x50d0b0; ...'`. If Q6 reads the comment through the same path it could misjudge documentation.

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- Data symbols too: `dcp refs ai_Unk6f1bb4` and `gm_CharacterStatistics` printed `definition=src/f3gm.c:2029 ... comment='/* The game data unit (0x4f9e30 ..'` instead of `/* 0x6f1bb4 */`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- `dcp refs gm_FreeBuilding` (`src/f3gm.c:3966`) and `dcp refs ai_Unk5a86c0` (unk_58bbd0.c's lead comment). Misleading when reading refs to learn what a function does.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- `dcp refs ai_Chars`: `definition=src/ahm.c:1245 comment='/* ahm.c -- the alchemist building and the recipes ...'` (ahm.c's lead comment); `dcp refs gm_PlayerRecord`: f3gm's lead comment.
