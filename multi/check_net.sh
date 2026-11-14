#!/bin/bash
# Run on any laptop: can it see the others?
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
for n in D T P A; do
  v="${n}_IP"; ip="${!v}"; pv="${n}_AGENT_PORT"; port="${!pv:-8800}"
  ping -c1 -W2 "$ip" >/dev/null 2>&1 && echo "ping  $n ($ip): ok" || echo "ping  $n ($ip): NO ANSWER"
done
GW="${GATEWAY_PORT:-8600}"
if [ "${TLS:-0}" = "1" ]; then
  [ -f "$TLS_DIR/node.crt" ] && echo "tls certificates: $TLS_DIR" || echo "tls certificates: MISSING in $TLS_DIR"
  curl -s -m3 --cacert "$TLS_DIR/ca.crt" "https://$D_IP:3443/" -o /dev/null -w "%{http_code}" | grep -q "^[0-9]" && echo "dashboard https://$D_IP:3443: reachable (TLS verified)" || echo "dashboard https://$D_IP:3443: NOT REACHABLE or certificate not trusted"
fi
PYTHONPATH="$ROOT/network" python3 -c "
from chainlib import Chain
print('fabric gateway $D_IP:$GW: ok, last event id', Chain().head())" 2>/dev/null || echo "fabric gateway $D_IP:$GW: NOT REACHABLE (start_D.sh running? TLS/certificates the same on both sides?)"
for n in T P; do
  v="${n}_IP"; ip="${!v}"; pv="${n}_AGENT_PORT"; port="${!pv:-8800}"
  if [ -n "$(eval echo \$AGENT_SECRET_$n)" ]; then
    python3 "$ROOT/multi/agent_call.py" $n GET /health 2>&1 | grep -q '"ok"' && echo "agent $n http://$ip:$port: ok (signed answer verified)" || echo "agent $n http://$ip:$port: not running or not authentic (normal before start_$n.sh)"
  else
    [ "${TLS:-0}" = "1" ] && { echo "agent $n: unsigned probe skipped (TLS needs a certificate)"; continue; }
    curl -s -m3 -o /dev/null -w "%{http_code}" "http://$ip:$port/health" | grep -q 401 && echo "agent $n http://$ip:$port: up (refuses unsigned requests, as it should)" || echo "agent $n http://$ip:$port: no answer from here (normal on A after lockdown)"
  fi
done
