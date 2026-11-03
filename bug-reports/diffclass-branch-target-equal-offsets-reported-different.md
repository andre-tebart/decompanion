# diffclass: branch targets reported as different when both offsets are equal

**Project:** gildegold, match-base session (wrap f5440ae)
**Severity:** not critical (wrong grade, no failure)

## What happened
`dcp diffclass gm_FreeStallCapacity` (0x50acf0) shows only one non-order/slots finding, and it contradicts itself:

```
branch targets differ (2): jg at +0x35: ours to +0x76, the original's to +0x76;
                           jge at +0x72: ours to +0x76, the original's to +0x76
```

Both sides jump to +0x76. In the epilogue the register pops come in a different order (ebx and edi swapped), so the instruction at the target offset pairs with a different instruction on the other side. The check seems to compare the paired target *instructions* rather than the target offsets.

## Effect
Every other hunk is order/slots, which counts as shape. Because of this check the function is held at draft and sent to the deep queue, when it should be graded shape.

## Expected
When both target offsets are the same (or the targets fall on the same position in a block that differs only by order/slots), this should not count as a branch-target difference.

## Repro
In gildegold: `dcp diffclass gm_FreeStallCapacity`. The check is in grade/diffclass.
