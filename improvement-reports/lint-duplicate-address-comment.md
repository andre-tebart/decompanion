# Lint: flag a comment duplicated above a definition

- **Source:** match-base session 2026-11-02 (gildegold), worker 58
- **Area:** `dcp lint` / Q6
- **Problem:** 0x4fbe90's address comment appeared twice back to back in src/f3gm.c (~900 characters each); nothing reported it, found only by reading.
- **Proposal:** a lint (or Q6) finding for identical consecutive comments above a definition.
- **Cost of not having it:** none this time; noise for later readers and in `dcp refs` output.
