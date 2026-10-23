#!/bin/bash
# Starts the lab: chain, contract, containers, parser. Dashboard is started separately.
ROOT="$(cd "$(dirname "$0")" && pwd)"
rpc() { curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://127.0.0.1:8545 | grep -q result; }
cd "$ROOT/blockchain" || exit 1
if ! rpc; then
  echo "starting hardhat node..."
  nohup npx hardhat node --hostname 0.0.0.0 > /tmp/hardhat.log 2>&1 &
  for i in $(seq 1 30); do sleep 1; rpc && break; done
fi
rpc || { echo "FAIL: chain not reachable"; exit 1; }
npx hardhat run scripts/deploy.js --network localhost || { echo "FAIL: deploy"; exit 1; }
cd "$ROOT"
cp deployments/localhost.json dashboard/public/localhost.json
docker compose rm -sf peer >/dev/null 2>&1   # fresh peer avoids stale localhost.json mount
docker compose up -d --build
docker cp deployments/localhost.json target:/opt/shield/localhost.json
docker compose up -d --force-recreate peer >/dev/null 2>&1
docker exec target pkill -f ssh_parser.py 2>/dev/null
docker exec -d -e COREPORT=1 target sh -c "cd /root/detector && python3 -u ssh_parser.py >> /var/log/parser.out 2>&1"
sleep 5

# tools needed by network/real_runs.sh (lost when containers are recreated)
docker exec target sh -c "which pkill >/dev/null || (apt-get update -qq && apt-get install -y -qq procps >/dev/null 2>&1)"
docker exec attacker sh -c "which pkill >/dev/null && which python3 >/dev/null || (apt-get update -qq && apt-get install -y -qq procps python3 >/dev/null 2>&1)"
"$ROOT/network/block_immunise.sh" 203.0.113.1 >/dev/null 2>&1   # warm-up: the first report is slow
echo "LAB READY. Start the dashboard in another terminal: cd dashboard && npm run dev"
