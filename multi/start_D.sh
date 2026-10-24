#!/bin/bash
# Laptop D: start the chain, deploy the contract, then run the dashboard (stays in the foreground).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
rpc() { curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://127.0.0.1:8545 | grep -q result; }
cd "$ROOT/blockchain" || exit 1
if ! rpc; then
  echo "starting hardhat node on 0.0.0.0:8545 ..."
  nohup npx hardhat node --hostname 0.0.0.0 > /tmp/hardhat.log 2>&1 &
  for i in $(seq 1 30); do sleep 1; rpc && break; done
fi
rpc || { echo "FAIL: chain not reachable"; exit 1; }
npx hardhat run scripts/deploy.js --network localhost || { echo "FAIL: deploy"; exit 1; }
cd "$ROOT"
cp deployments/localhost.json dashboard/public/localhost.json
echo
echo "Chain:     http://$D_IP:8545"
echo "Dashboard: http://localhost:3000   (T and P fetch the contract from http://$D_IP:3000/localhost.json)"
echo "Now start T and P (sudo multi/start_T.sh, sudo multi/start_P.sh). Dashboard starting ..."
cd "$ROOT/dashboard"
MULTI=1 TARGET_AGENT="http://$T_IP:8800" PEER_AGENT="http://$P_IP:8800" ATTACKER_IP="$A_IP" \
  exec npm run dev -- -H 0.0.0.0
