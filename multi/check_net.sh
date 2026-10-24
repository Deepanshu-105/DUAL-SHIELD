#!/bin/bash
# Run on any laptop: can it see the others?
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
for n in D T P A; do
  v="${n}_IP"; ip="${!v}"
  ping -c1 -W2 "$ip" >/dev/null 2>&1 && echo "ping  $n ($ip): ok" || echo "ping  $n ($ip): NO ANSWER"
done
curl -s -m3 -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "http://$D_IP:8545" | grep -q result && echo "chain http://$D_IP:8545: ok" || echo "chain http://$D_IP:8545: NOT REACHABLE"
curl -s -m3 "http://$D_IP:3000/localhost.json" | grep -q address && echo "dashboard file http://$D_IP:3000/localhost.json: ok" || echo "dashboard http://$D_IP:3000: NOT REACHABLE"
for n in T P; do
  v="${n}_IP"; ip="${!v}"
  curl -s -m3 -H "X-Token: $AGENT_TOKEN" "http://$ip:8800/health" | grep -q ok && echo "agent $n http://$ip:8800: ok" || echo "agent $n http://$ip:8800: not running (normal before start_$n.sh)"
done
