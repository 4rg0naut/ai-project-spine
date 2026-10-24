#!/bin/bash
# Project gates. Add a gate only when a failure demands one (BUGS.md).
set -u
cd "$(dirname "$0")/.."
ok=1
python3 tools/spine.py verify || ok=0
python3 tools/spine.py claim conform || ok=0
python3 tools/spine.py selftest || ok=0
[ "$ok" = 1 ] && { echo "ALL GATES PASS"; exit 0; }
echo "GATES FAILED"; exit 1
