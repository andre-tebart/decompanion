# A view of a datum's or parameter's users by offset and type

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp refs / typing
- **Problem:** overlapping view types keep coming up. The original stores ints into a `float *out` record. A struct layout for one function ripples through the other users and their byte matches, so the worker fell back to `((int *)out)[7]`. Q4 does not flag this, though it is no truer than the old raw access.
- **Proposal:** a `dcp refs`-style view listing the users of a datum or parameter by offset and access type, to decide whether a typed record is affordable.
- **Cost of not having it:** judgement calls on two functions.
