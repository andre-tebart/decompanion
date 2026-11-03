# One read query for type layout

- **Priority:** P2 · **Size:** M

## Problem

Workers search headers by hand for:

- a struct of a given size or stride, or with a field at an offset;
- the other views of one record;
- a member's uses by offset and type.

## Task

Add one read query, through clang:

- struct types by size and by field offset;
- a member's uses by offset and type;
- other headers' structs with fields at the same offsets.

Several views of one record go against §8.8 (one declaration per object). That is not decidable as a finding yet;
later this could become derived findings on types.

## Rejected

A separate `struct suggest` command or a padding-split command.

## Reports

- types-by-stride-or-field-query
- types-duplicate-views-lint (4)
- struct-split-padding-command
- datum-users-by-offset-and-type
- asmdiff-field-names-for-offsets (H side, if at all)
