# After a full hand rename and build, `dcp rename` refuses ("OLD and NEW are the same") and names.log can never record it

- **Source:** match-base session 2026-11-02 (gildegold), worker 34
- **Severity:** minor
- **What happened:** after `sed`-renaming ai_Unk498b80 to ai_DecideUpgradeResidence in src/am.c and include/am.h and rebuilding, `dcp rename 0x498b80 ai_DecideUpgradeResidence --why '...'` printed `note: 0x498b80 is ai_DecideUpgradeResidence (the ledger's name on target exe)` then `error='OLD and NEW are the same name ai_DecideUpgradeResidence'`, exit 1. The ledger takes names from the source, so once the old name is gone the rename can't be logged. The skill's "a name written by hand is completed by the rename" holds only while the old name remains somewhere.
- **Expected:** when the address's ledger name already equals NEW but names.log has no entry for it, write the names.log entry (previous name from git / the baseline) instead of refusing; or offer `dcp rename --log-only 0xADDR NEW --why ...`.
- **Repro:** `sed -i 's/ai_Unk498b80/ai_DecideUpgradeResidence/g' src/am.c include/am.h`, `uv run dcp build`, `uv run dcp rename 0x498b80 ai_DecideUpgradeResidence --why x` (gildegold before 61cfc0d).
- **Impact:** ~3 calls (revert, rebuild, rename again).
- **Related:** rename-refused-hand-written-name-other-signature.md, rename-repeat-duplicate-names-log.md
