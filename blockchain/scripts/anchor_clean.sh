#!/usr/bin/env bash
# Take a clean snapshot and anchor its Merkle root on the Fabric ledger for IP (default 172.30.0.12).
set -e
IP=${1:-172.30.0.12}
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$ROOT_DIR/blockchain/.venv/bin/python3"
cd "$ROOT_DIR/ransomware"
"$PY" rollback.py snapshot data/sample >/dev/null
ROOT=$("$PY" -c "import snapshot; print(snapshot.snapshot('data/snapshot')['root'])")
cd "$ROOT_DIR"
"$PY" blockchain/scripts/anchor_snapshot.py "$IP" "$ROOT" | grep -E "anchored|matches" || true
echo "ANCHORED clean root $ROOT for $IP"
