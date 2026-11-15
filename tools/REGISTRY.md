# Tool registry - ai-project-spine

Every executable under tools/ gets a row the day it lands (verify warns
about unregistered executables; the ledger knows, so stay registered):

| path | status | purpose |
|------|--------|---------|
| tools/spine.py | canonical | the spine gate itself (0.5.0) |
| tools/difftest.py | canonical | differential gate: keeper (Rust) vs spine.py, same scratch, byte-parity or DIFF |

Outside tools/ but same discipline: `keeper/` (Rust subset service,
binary at keeper/target/debug/keeper), `keeper/launchd/` (LaunchDaemon
template).
