# `dcp escalate -h`: list the phrases the reason filter refuses

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** dcp escalate
- **Problem:** reasons had to be worded carefully to get past the wording filters ("not reconciled" and similar), and the filter's phrases are not documented.
- **Proposal:** if the filter can't be relaxed, list the forbidden phrases in `dcp escalate -h`. Related: escalate-why-file.md
- **Cost of not having it:** none this session.
