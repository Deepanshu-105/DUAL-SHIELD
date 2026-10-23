#!/usr/bin/env bash
# Take a clean snapshot and anchor its Merkle root on-chain for IP (default 172.30.0.12).
set -e
IP=${1:-172.30.0.12}
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$ROOT_DIR/blockchain/.venv/bin/python3"
cd "$ROOT_DIR/ransomware"
"$PY" rollback.py snapshot data/sample >/dev/null
ROOT=$("$PY" -c "import snapshot; print(snapshot.snapshot('data/snapshot')['root'])")
cd "$ROOT_DIR"
"$PY" - << PYEOF
import json
from web3 import Web3
dep = json.load(open("deployments/localhost.json"))
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
c = w3.eth.contract(address=dep["address"], abi=dep["abi"])
a = w3.eth.accounts[0]
if c.functions.stakes(a).call() == 0:
    w3.eth.wait_for_transaction_receipt(c.functions.registerNode().transact({"from": a, "value": w3.to_wei(1, "ether")}))
PYEOF
"$PY" blockchain/scripts/anchor_snapshot.py "$IP" "$ROOT" | grep -E "gas used|matches"
echo "ANCHORED clean root $ROOT for $IP"
