# Measurement schema (v0.5)

One JSON object per line in data/measurements.jsonl, append-only:

{"m_id","ts","command","value","unit","observed","source_claim","by"}

- value MUST equal the command's stdout (minus trailing newline) at
  append time - `measure append` runs the command and refuses a mismatch.
- source_claim must resolve to an issued claim id (exact or unique prefix).
- `measure audit` re-runs every command: OK / DRIFT lines, exit 1 on drift.
- The point (from silicon-ledger): a number without the command, unit and
  observed text that produced it is decoration, not measurement.
