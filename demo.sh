#!/bin/bash
# Dual-Shield end-to-end demo: attack -> block -> immunise -> kill -> rollback
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/ransomware" || exit 1
python3 -c "import cryptography, watchdog" 2>/dev/null || { echo "FAIL: python modules missing. Run deactivate (leave .venv) or pip3 install watchdog cryptography"; exit 1; }
banner() { echo; echo "=============== $1 ==============="; sleep 2; }

banner "RESET"
docker exec target ipset flush city_blacklist 2>/dev/null
docker exec peer ipset flush city_blacklist 2>/dev/null
ATTACK_IP="203.0.113.$((RANDOM % 200 + 20))"
: > evidence/watch.log
python3 rollback.py snapshot data/sample || echo "WARN: snapshot failed"

banner "KILL RULE ARMED (watcher on data/sample_copy)"
python3 detect.py watch data/sample_copy --kill >> evidence/watch.log 2>&1 &
WATCH_PID=$!
sleep 2

banner "1. ATTACK (mock ransomware, --delay 0.5)"
python3 mock_crypto.py --delay 0.5 || echo "attack process ended (killed or finished)"
sleep 2

banner "2. BLOCK (target blocks, reports to chain)"
echo "attacker IP: $ATTACK_IP"
"$ROOT/network/block_immunise.sh" "$ATTACK_IP" | tee /tmp/block_immunise.out

banner "3. IMMUNISE (peer blocks after consensus)"
docker exec peer ipset list city_blacklist | grep "$ATTACK_IP" && echo "IMMUNISED: peer blocks $ATTACK_IP" || echo "WARN: peer does not block $ATTACK_IP"

banner "4. KILL (result from the watcher)"
grep -E "KILL_TRIGGER|KILLED|KILL_NO_TARGET" evidence/watch.log || echo "no kill event found"

banner "5. ROLLBACK"
python3 rollback.py restore data/sample_copy || echo "WARN: rollback failed"

kill $WATCH_PID 2>/dev/null
banner "DEMO COMPLETE"
echo "flagged files: $(grep ' FLAGGED ' evidence/watch.log | awk '{print $5}' | sort -u | wc -l)"
echo "kills:         $(grep -c ' KILLED pid=' evidence/watch.log)"
exit 0
