#!/bin/bash
# Run on any laptop: can it see the others?
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
for n in D T P A; do
  v="${n}_IP"; ip="${!v}"
  ping -c1 -W2 "$ip" >/dev/null 2>&1 && echo "ping  $n ($ip): ok" || echo "ping  $n ($ip): NO ANSWER"
done
if [ "${TLS:-0}" = "1" ]; then
  [ -f "$TLS_DIR/node.crt" ] && echo "tls certificates: $TLS_DIR" || echo "tls certificates: MISSING in $TLS_DIR"
  curl -s -m3 --cacert "$TLS_DIR/ca.crt" "https://$D_IP:3443/localhost.json" | grep -q address && echo "dashboard file https://$D_IP:3443/localhost.json: ok (TLS verified)" || echo "dashboard https://$D_IP:3443: NOT REACHABLE or certificate not trusted"
  (exec 3<>/dev/tcp/$D_IP/8546) 2>/dev/null && echo "chain tunnel $D_IP:8546: port open (mutual TLS required)" || echo "chain tunnel $D_IP:8546: NOT REACHABLE"
else
curl -s -m3 -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "http://$D_IP:8545" | grep -q result && echo "chain http://$D_IP:8545: ok" || echo "chain http://$D_IP:8545: NOT REACHABLE"
curl -s -m3 "http://$D_IP:3000/localhost.json" | grep -q address && echo "dashboard file http://$D_IP:3000/localhost.json: ok" || echo "dashboard http://$D_IP:3000: NOT REACHABLE"
fi
for n in T P; do
  v="${n}_IP"; ip="${!v}"
  if [ -n "$(eval echo \$AGENT_SECRET_$n)" ]; then
    python3 "$ROOT/multi/agent_call.py" $n GET /health 2>&1 | grep -q '"ok"' && echo "agent $n http://$ip:8800: ok (signed answer verified)" || echo "agent $n http://$ip:8800: not running or not authentic (normal before start_$n.sh)"
  else
    [ "${TLS:-0}" = "1" ] && { echo "agent $n: unsigned probe skipped (TLS needs a certificate)"; continue; }
    curl -s -m3 -o /dev/null -w "%{http_code}" "http://$ip:8800/health" | grep -q 401 && echo "agent $n http://$ip:8800: up (refuses unsigned requests, as it should)" || echo "agent $n http://$ip:8800: no answer from here (normal on A after lockdown)"
  fi
done
