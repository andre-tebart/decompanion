# `dcp session start` prints layout-session guidance in a match-base session

- **Source:** match-base session 2026-11-01 (gildegold)
- **Severity:** minor (confusing output)
- **What happened:** the output says "The session clock runs (30 minutes) … wrap up once it says over=yes" and points to `dcp layout next`. The dcp-match-base skill counts a session in functions (8), so this guidance does not apply and could make an agent stop early.
- **Expected:** guidance that matches the session kind.
- **Impact:** none this time.
