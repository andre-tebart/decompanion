# match-base skill: say how to commit undeclared data inside a unit's own block

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Area:** dcp-match-base skill, section 2.5
- **Problem:** section 2.5 covers only `full_data_` gap blocks. Undeclared bytes inside a unit's own block (0x5eec6c in unk_575860) are a different case; the worker guessed the commit form ("data ... (typing)", 33f1640) and added three more constants inside function commits.
- **Proposal:** one line covering this case (declare in the unit, own typing commit, commit message form).
- **Cost of not having it:** small.
- **Related:** skill-typing-commit-split.md
