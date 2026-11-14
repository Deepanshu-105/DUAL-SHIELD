#!/bin/bash
# Single-machine lab (Docker containers for target, peer, attacker) on Hyperledger Fabric. No gas, no Hardhat.
# Fabric itself runs natively on this machine (fabric/deploy/network.sh); the containers reach the gateway at host.docker.internal:8600.
# Dashboard is started separately. Needs once: fabric/deploy/install_fabric.sh, and npm install --omit=dev in fabric/chaincode/cityshield and fabric/gateway.
ROOT="$(cd "$(dirname "$0")" && pwd)"
FAB="$ROOT/fabric"
[ -x "$FAB/bin/peer" ] || { echo "Run once: fabric/deploy/install_fabric.sh (and npm install --omit=dev in fabric/chaincode/cityshield and fabric/gateway)"; exit 1; }
"$FAB/deploy/network.sh" up || { echo "FAIL: Fabric network"; exit 1; }
pkill -f "fabric/gateway/server.js" 2>/dev/null; sleep 1
nohup env GATEWAY_PORT=8600 GATEWAY_HOST=0.0.0.0 GATEWAY_LAB=1 node "$FAB/gateway/server.js" > /tmp/fabric_gateway.out 2>&1 &
export GATEWAY_URL=http://127.0.0.1:8600
PY="$ROOT/blockchain/.venv/bin/python3"; [ -x "$PY" ] || PY=python3
export PYTHONPATH="$ROOT/network"
for i in $(seq 1 40); do "$PY" -c "from chainlib import Chain; Chain().head()" 2>/dev/null && break; sleep 1; done
"$PY" "$ROOT/network/chain_setup.py" --approve || { echo "FAIL: node approval"; exit 1; }
"$PY" "$ROOT/network/chain_setup.py" --register 1 && "$PY" "$ROOT/network/chain_setup.py" --register 2
unset GATEWAY_URL PYTHONPATH
docker compose up -d --build
docker compose up -d --force-recreate peer >/dev/null 2>&1
docker exec target pkill -f ssh_parser.py 2>/dev/null
docker exec -d -e COREPORT=1 target sh -c "cd /root/detector && python3 -u ssh_parser.py >> /var/log/parser.out 2>&1"
sleep 5

# tools needed by network/real_runs.sh (lost when containers are recreated)
docker exec target sh -c "which pkill >/dev/null || (apt-get update -qq && apt-get install -y -qq procps >/dev/null 2>&1)"
docker exec attacker sh -c "which pkill >/dev/null && which python3 >/dev/null || (apt-get update -qq && apt-get install -y -qq procps python3 >/dev/null 2>&1)"
"$ROOT/network/block_immunise.sh" 203.0.113.1 >/dev/null 2>&1   # warm-up: the first report is slow
# demo sample folder and detector baseline (git-ignored, created once on a fresh clone)
"$ROOT/ransomware/setup_sample.sh" >/dev/null 2>&1 || echo "WARN: ransomware sample setup failed (pip install watchdog cryptography?)"

# anchor the clean snapshot on the Fabric ledger (the dashboard rollback checks it)
GATEWAY_URL=http://127.0.0.1:8600 "$ROOT/blockchain/scripts/anchor_clean.sh" >/dev/null 2>&1 || echo "WARN: clean-state anchor failed (rollback button will say ANCHOR_MISSING)"

echo "LAB READY (Hyperledger Fabric). Start the dashboard in another terminal: cd dashboard && npm run dev"
