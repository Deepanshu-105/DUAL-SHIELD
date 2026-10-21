#!/bin/bash
# Dual-Shield end-to-end demo: attack -> block -> immunise -> kill -> rollback
cd "$(dirname "$0")/ransomware" || exit 1
banner() { echo; echo "=============== $1 ==============="; sleep 2; }

banner "RESET"
: > evidence/watch.log
python3 rollback.py snapshot data/sample || echo "WARN: snapshot failed"

banner "KILL RULE ARMED (watcher on data/sample_copy)"
python3 detect.py watch data/sample_copy --kill >> evidence/watch.log 2>&1 &
WATCH_PID=$!
sleep 2

banner "1. ATTACK (mock ransomware, --delay 0.5)"
python3 mock_crypto.py --delay 0.5 || echo "attack process ended (killed or finished)"
sleep 2

banner "2. BLOCK (STUB: M1/M2 firewall step)"
echo "STUB: block attacker IP 203.0.113.181"

banner "3. IMMUNISE (STUB: M1/M2 peer broadcast)"
echo "STUB: notify peer nodes B and C"

banner "4. KILL (result from the watcher)"
grep -E "KILL_TRIGGER|KILLED|KILL_NO_TARGET" evidence/watch.log || echo "no kill event found"

banner "5. ROLLBACK"
python3 rollback.py restore data/sample_copy || echo "WARN: rollback failed"

kill $WATCH_PID 2>/dev/null
banner "DEMO COMPLETE"
echo "flagged files: $(grep ' FLAGGED ' evidence/watch.log | awk '{print $5}' | sort -u | wc -l)"
echo "kills:         $(grep -c ' KILLED pid=' evidence/watch.log)"
exit 0
