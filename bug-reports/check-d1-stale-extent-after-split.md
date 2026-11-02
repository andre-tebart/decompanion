# `dcp check --strict` D1 uses a stale extent after a following object is defined

- **Source:** match-base session 2026-11-01 (gildegold), worker 12
- **Severity:** minor
- **What happened:** after defining sv_SkyFair at 0x6238a8, `dcp check --strict` warned "D1 0x006238a4..0x006238ac ai_Unk6238a4 ... the object gives it 8 bytes, the symbol at 0x6238a8 leaves 4". ai_Unk6238a4 is a 4-byte int; the 8-byte extent is stale ledger data from the old room.
- **Expected:** recompute the extent when a following symbol appears, or name where the 8 comes from.
- **Repro:** `uv run dcp check --strict` at gildegold 3b912d2.
- **Impact:** a few minutes checking the layout.
- **Related:** ../improvement-reports/data-size-vs-original-extent.md
