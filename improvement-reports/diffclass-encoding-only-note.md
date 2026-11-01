# diffclass: explain encoding-only differences (short vs long branches)

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** diffclass / grade
- **Problem:** `ls_WriteMessageQueues` graded shape with `dist='0 ins / 517 bytes, size 778 vs 774'` and `B2 shape: identical instructions`. The bytes come from jcc rel8 vs rel32 due to block layout; a `--plain` asmdiff was needed to confirm nothing else differed.
- **Proposal:** print "encoding only: N branches long vs short (block layout)".
- **Repro:** `uv run dcp grade ls_WriteMessageQueues` in gildegold at bfcf2ba.
- **Cost of not having it:** about 2 minutes.
