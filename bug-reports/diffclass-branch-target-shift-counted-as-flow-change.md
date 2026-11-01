# diffclass counts a moved branch target as changed control flow

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Severity:** minor (wrong verdict)
- **What happened:** `ord_ComputeStatistics` had no `code` hunks left, only fpu, slots and order. The verdict still said draft because of "branch targets differ (1): jne at +0x350: ours to +0x309, the original's +0x301". The jump was the same; the loop head had moved 8 bytes because an earlier FPU hunk was longer.
- **Expected:** when the aligned target instructions are equal, put the shift down to the earlier hunk (or class it as fpu/shape) instead of counting it as a flow difference.
- **Repro:** `dcp diffclass ord_ComputeStatistics` at gildegold commit 19f0597.
- **Impact:** about 10 minutes, and one function escalated to deep that was arguably shape.
