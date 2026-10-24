# State

Project: ai-project-spine. Created 2026-10-21 by ai-project-spine 0.3.1.
Purpose: the fleet's project skeleton generator - one stdlib file you
download and execute; it lands a rule-bearing starter kit (AGENTS.md,
STATE.md, decaying TODO.md, decisions/bugs/lessons) plus a self-contained
OpenClaims v0.1 ledger gate. This repo is self-hosted: it carries its own
spine ledger since 2026-10-21.

- Phase: v0.4 - preflight (R7), close, sessions ingest, golden ritual,
  orphan-coverage, retest enforcement, session-standardized producer.
- Open risks: none recorded yet (see BUGS.md).

Next command:
    python3 tools/spine.py verify
    - then bash tests/run.sh (verify + conform + selftest).

Resume rule: this file ends with the literal next command. Any session
(quota death, power cut, new agent) restarts from this file alone.

Closed 2026-10-24T19:07:55Z by openfox-builder: supersedes (nothing) - v0.4 released: R7+preflight, close, sessions ingest, --with-golden, orphan-coverage, retest enforcement, session-standardized producer; AI_dev named as earning customer
