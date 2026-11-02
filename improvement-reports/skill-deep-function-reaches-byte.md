# Skill: what to do when a deep-tagged function silently reaches byte

- **Source:** match-base session 2026-11-02 (gildegold), worker 22
- **Area:** dcp-match-base skill, wrap
- **Problem:** an AIBLD union member added to ai.h recompiled 24 units and raised ai_Unk483a60 (tagged deep) from shape to byte. The skill doesn't say whether to `dcp escalate --clear` it or leave it for the deep queue; the worker left it.
- **Proposal:** one sentence in the skill (or have the wrap clear `@deep` automatically when a function reaches byte, as happened for ocmd_SetCameraToDummy earlier).
- **Repro:** wrap report at gildegold 9dc704f.
- **Cost of not having it:** none; doubt only.
