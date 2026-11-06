#!/bin/bash
# Laptop D: start the chain, deploy the contract, then run the dashboard (stays in the foreground).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
[ ${#DASH_PASS} -ge 8 ] && [ ${#AGENT_SECRET_T} -ge 16 ] && [ ${#AGENT_SECRET_P} -ge 16 ] || { echo "Set DASH_PASS, AGENT_SECRET_T and AGENT_SECRET_P in multi/config.env (run multi/gen_secrets.sh)"; exit 1; }
rpc() { curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://127.0.0.1:8545 | grep -q result; }
cd "$ROOT/blockchain" || exit 1
if ! rpc; then
  echo "starting hardhat node on 0.0.0.0:8545 ..."
  nohup npx hardhat node --hostname "$([ "${TLS:-0}" = "1" ] && echo 127.0.0.1 || echo 0.0.0.0)" > /tmp/hardhat.log 2>&1 &
  for i in $(seq 1 30); do sleep 1; rpc && break; done
fi
rpc || { echo "FAIL: chain not reachable"; exit 1; }
npx hardhat run scripts/deploy.js --network localhost || { echo "FAIL: deploy"; exit 1; }
cd "$ROOT"
cp deployments/localhost.json dashboard/public/localhost.json
echo
echo "Chain:     http://$D_IP:8545   (run sudo multi/lockdown.sh D so only T and P can reach it)"
echo "Dashboard: http://localhost:3000   login: operator / DASH_PASS   (T and P fetch the contract from http://$D_IP:3000/localhost.json)"
echo "Now start T and P (sudo multi/start_T.sh, sudo multi/start_P.sh). Dashboard starting ..."
if [ "${TLS:-0}" = "1" ]; then
  pkill -f tls_proxy.py 2>/dev/null
  nohup python3 -u "$ROOT/multi/tls_proxy.py" server --listen 0.0.0.0:8546 --to 127.0.0.1:8545 --allow dualshield-target,dualshield-peer > /var/log/tls_chain.out 2>&1 &
  nohup python3 -u "$ROOT/multi/tls_proxy.py" server --listen 0.0.0.0:3443 --to 127.0.0.1:3000 --no-client-cert > /var/log/tls_dash.out 2>&1 &
  echo "TLS on: chain RPC only via mutual TLS on :8546, dashboard at https://$D_IP:3443 (trust multi/tls/dashboard/ca.crt in your browser)"
fi
if [ "${DISCOVERY:-0}" = "1" ]; then
  pkill -f multi/registry.py 2>/dev/null
  nohup env AGENT_SECRET_T="$AGENT_SECRET_T" AGENT_SECRET_P="$AGENT_SECRET_P" REGISTRY_PORT="${REGISTRY_PORT:-8801}" python3 -u "$ROOT/multi/registry.py" > /var/log/registry.out 2>&1 &
  echo "Registry:  :${REGISTRY_PORT:-8801}   (T and P find each other through it; log /var/log/registry.out)"
fi
SCHEME=http; [ "${TLS:-0}" = "1" ] && SCHEME=https
cd "$ROOT/dashboard"
DISCOVERY="${DISCOVERY:-0}" TLS="${TLS:-0}" MULTI=1 TARGET_AGENT="$SCHEME://$T_IP:8800" PEER_AGENT="$SCHEME://$P_IP:8800" ATTACKER_IP="$A_IP" \
  exec npm run dev -- -H "$([ "${TLS:-0}" = "1" ] && echo 127.0.0.1 || echo 0.0.0.0)"
