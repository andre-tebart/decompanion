# Knowledge note or `dcp hint` for known VC6 optimizer behaviours

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** skill docs / new command
- **Problem:** `snd_UpdateRain` needed `(float)(x * 88.9f) / d` to stop VC6 folding `x * 88.9f * (1/d)` into one constant. Finding the spelling took several build–asmdiff rounds.
- **Proposal:** a short note in the skill, or a `dcp hint` command, listing known VC6 behaviours and the spellings that steer them:
  - constant folding
  - sharing one reciprocal across divisions by the same value
  - merging identical call tails (see diffclass-tail-epilogue-class.md)
  - threading jumps past known branches
  - per-scope stack-slot packing
- **Cost of not having it:** about 30 minutes across the float-heavy functions.
