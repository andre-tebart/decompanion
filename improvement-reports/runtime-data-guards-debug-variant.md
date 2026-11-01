# Runtime guards for data corruption in debug variants

- **Source:** play debugging session 2026-11-01 (gildegold)
- **Area:** dcp run / build variants (docs/run.md), the link of a variant
- **Problem:** the three bugs of this session (see `data-size-vs-original-extent.md`,
  `address-vs-value-hunk-class.md`) all showed up far from their cause. A header read overran its 4-byte
  global and silently overwrote about 30 neighbours. A null buffer passed to `vfs_fread` returned -1, which
  `ls_Read` counts as success, and the crash came three readers later. `dcp run --debug` names the crash
  site well, but the crash site was never the bug.
- **Proposal:** variant options that a run profile can turn on:
  1. `guard_data = true`: link the variant with a guard word between data symbols (or after each one
     whose size is a draft), fill it with a pattern, and check the pattern from a hook (once per frame, or
     in the crash report). The report would name the first overwritten guard: "guard after ai_Unk76f920
     (ls.c) overwritten".
  2. A list of `assert_args`, e.g. "argument 1 of vfs_fread / vfs_fwrite is not null", compiled in as a
     wrapper in the variant only, so the run stops at the faulty call.
- **Repro:** gildegold commit 258ff9e, `REA_START=tutorial dcp run play`.
- **Cost of not having it:** each crash needed minidump reading by hand (the debug link's addresses, the
  stack slots of a draft function) before the cause could even be located.
