# Flag frame slots the original reads but never writes

- **Source:** match-base session 2026-11-02 (gildegold), worker 41
- **Area:** `dcp grade` / `dcp asmdiff`
- **Problem:** in ai_PickActionBuilding (0x4a63f0) and ai_PickActionBuildings (0x4a6570) both liking bounds compare against `[esp+0x5c]`, the filter record's float at +0x44, which the function never stores to (an original quirk, reproduced and commented). The worker first took it for the lo/hi parameters and lost time on frame arithmetic.
- **Proposal:** note "the original reads frame slot +0x5c (inside local q at +0x44) that no instruction writes": an uninitialised read, i.e. a field of a local struct or an original bug. Earlier: ai_PickLeastLikedRival's draft read an uninitialised local where the original read a real field (worker 38), so the reverse check (ours reads an unwritten slot) is useful too.
- **Repro:** `uv run dcp asmdiff ai_PickActionBuilding` at gildegold 904e84b.
- **Cost of not having it:** ~10 minutes.
