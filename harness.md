# Harness contract - . (spine 0.5.0)

Step zero, every session, before any task:
    python3 tools/spine.py verify        # must exit 0
    python3 tools/spine.py preflight "what you are about to do"

Deny-paths (direct edits here are FORBIDDEN - use the verb that owns them):
- claims/claims.jsonl  -> claim emit|verify|dispute|retract, sign, close,
  todo, loop, preflight (audits), db (receipts), hooks (accountability)
- data/db/records.jsonl -> db add|link|supersede (append-only snapshots)
- data/measurements.jsonl -> measure append (audit re-runs, never writes)
- data/kindex.jsonl + data/derived.json -> index build (derived, never hand)
- tools/REGISTRY.md -> register a tool in the same commit that adds it
After any legal hand edit of an attested file: sign --by WHO --reason WHY.

Machine surfaces: `mcp` (stdio) and `mcp --http PORT` expose
verify/preflight/db/measure/loop/search/dayreport as native tools; unattended
runs are accountable via `dayreport` and hooks-bypass.log (rule R6/R7).
