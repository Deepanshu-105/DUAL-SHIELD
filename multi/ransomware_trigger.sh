#!/bin/bash
# Run on D (or on T), NOT on A: A is blocked by then. Starts the watcher (kill rule) and the mock ransomware on T.
# It stands for "malware that is already inside T through another route". Nothing real is encrypted:
# the mock only touches ransomware/data/sample_copy.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
curl -s -X POST -H "X-Token: $AGENT_TOKEN" "http://$T_IP:8800/ransomware"; echo
echo "Watch laptop D: flagged files, kills, then click 'Roll back to clean state'."
