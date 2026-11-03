#!/bin/bash
# Run on D (or on T), NOT on A: A is blocked by then. Starts the watcher (kill rule) and the mock ransomware on T.
# It stands for "malware that is already inside T through another route". Nothing real is encrypted:
# the mock only touches ransomware/data/sample_copy.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
python3 "$ROOT/multi/agent_call.py" T POST /ransomware "{}"
echo "Watch laptop D: flagged files, kills, then click 'Roll back to clean state'."
