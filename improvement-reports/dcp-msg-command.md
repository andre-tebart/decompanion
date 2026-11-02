# `dcp msg TYPE`: show a network message's sender, wrapper, handler and field layout together

- **Source:** match-base session 2026-11-02 (gildegold), worker 24
- **Area:** new command
- **Problem:** six of eight functions this session were message senders/handlers sharing one 0x19/0x1f-byte layout: `cm_SendGraveOrder` with type N, and `cm_Send*` wrappers whose `m.type = 0x61/0x62` matches a `case` in cm.c's dispatch. GVMOVE and GVRAISE were worked out by grepping cm.c for the type, reading the handler, and checking the sender's stores in disasm.
- **Proposal:** `dcp msg 0x62` printing the type constant, sender(s), cm wrapper, cm handler case and the function it calls, plus the field offsets each side writes and reads (the struct layout in one step).
- **Cost of not having it:** ~4-5 calls per sender/handler pair.
- **Related:** twin-functions-together.md, similar-function-hint.md
