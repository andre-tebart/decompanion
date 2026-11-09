# An address used as a number: `&SYM + N` as a mask or constant

- **Priority:** P0 · **Size:** M (the check S, the lint M) · **Root:** R2

## Problem

From improvement-reports/symbol-arithmetic-constants.md (gildegold, 2026-11-08; severity critical, three live
runtime bugs): constants spelled `(unsigned)&SYM + N`. The value equals the original's only while SYM keeps the
original's link address. In the original's layout every check agrees, so no check fails:

- `ai_DecideBuildBusiness` stayed **byte** with `flags1c8 & (&txt_Keys + 0x181c0)` where the original tests
  `0x1000000`; `INIT_PROTO_MASK` = `&txt_Keys + 0x181bf` (meant `0xffffff`) hid the blacksmith's anvil at run time
  in our relink; `dd_RMask = &txt_Keys + 0x81c0` where the original stores `0xff0000`.
- M.contain misses them: the addend lies inside `txt_Keys` (0x168000 bytes).
- Comparing the relocated field by value (the report's proposal 1) does not help either: φ(txt_Keys) + 0x181c0 *is*
  0x1000000 at the original's layout. That is how the worker found the spelling. The value is right; it is the
  kind of the operand that is wrong.
- The same root cause: `p + N` where N is no multiple of `sizeof(*p)` silently rescales when p is retyped
  (gildegold `sv_MessageBox` crash, fixed in 3ad3bd2c).

## Task

1. **The check (refcheck, beside M.contain):** a relocated **immediate** of ours to a named data object that the
   instruction uses as a number, not as an address. These are the bitwise and multiplicative operations: `and`,
   `or`, `xor`, `test`, `imul`, `shl`/`shr`/`sar`, `rol`/`ror`. No compiler places an address there. Finding
   `M.addrnum` at **warn** with both values: ours at our relink when the link answers it, and the original's
   (`&txt_Keys + 0x181c0 is 0x1000000 at the original's layout: write the number`). Raise it to an error
   (ill-formed, like M.contain) once gildegold has none left.
2. **`dcp lint`:** a cast of an address to an integer type with a constant added (`(unsigned)&SYM + N`, `(int)SYM + N`)
   whose value is used as an integer (a mask, a comparison with a non-pointer, an assignment to an integer, a
   non-pointer argument). Pointer arithmetic `p + N` on a non-byte pointer where N is a constant and no multiple of
   `sizeof(*p)`.
3. **Sweep:** the report's audit as a one-time list for gildegold (121 `(unsigned)&SYM + 0x...` occurrences at
   f5f47ae9): each one either a true one-past-the-end / pointer limit, or a constant to write as a number.

## Rejected

- Value comparison of relocated operands with immediates as the main check (see above). It is still worth doing
  for the draft case where the instructions do not align, but census and M8 already cover that.

## Model

§8.7 (containment) generalised: an address is an address of its object, never a number that happens to equal one.

## Reports

- symbol-arithmetic-constants (improvement)
