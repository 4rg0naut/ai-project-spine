# ai-project-spine - agent start-here

Purpose: see STATE.md first block. Skeleton by ai-project-spine 0.4.0 2026-10-24.

Boot ritual (every session, in order):
1. Read STATE.md - it is the state and ends with the literal next command.
2. Run: python3 tools/spine.py verify   (must exit 0 before any work)
3. TODO.md entries are stale hypotheses until re-justified against gates
   and DECISIONS.md. Deleting one is a valid first act.

Rules live where they already live - never restate them here:
- decisions/contracts: DECISIONS.md    - open risks: BUGS.md
- intentions + decay mechanics: TODO.md header
- lessons: LESSONS/
- claims (cited, dated, chained): python3 tools/spine.py claim query

Editing prose is legal; then sign:
  python3 tools/spine.py sign --by WHO --reason "why"
This file stays short. If a line duplicates another file, delete it here.
