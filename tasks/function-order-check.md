# Function source order vs address order within a unit

- **Priority:** P2 · **Size:** S

## Problem

A unit's functions can sit in source in an order different from their addresses. Nothing reports it, although LINK
places a unit's functions in source order.

## Root cause

D4 checks the definition order of data only. No check compares a unit's function order with its address order. That is
part of the unit experiment (§4), which §10 says does not exist yet.

## Task

Add a derived check under the LINK order convention: report a unit whose function source order disagrees with its
address order, as the function analogue of D4. It is a rule, not a lint.

## Reports

- lint-function-out-of-address-order
