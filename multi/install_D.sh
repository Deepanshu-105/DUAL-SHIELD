#!/bin/bash
# Laptop D (dashboard + chain). No Docker, no sudo needed except for apt.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
sudo apt-get update -qq
sudo apt-get install -y git curl python3
if ! command -v node >/dev/null || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]; then
  echo "Node 22 is needed (Fabric chaincode and gateway need Node 18 or newer). Install it with nvm:"
  echo '  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash'
  echo '  (open a new terminal)  nvm install 22 && nvm use 22   then run this script again'
  exit 1
fi
if [ ! -x "$ROOT/fabric/bin/peer" ]; then "$ROOT/fabric/deploy/install_fabric.sh"; fi   # Hyperledger Fabric 2.5 binaries, no Docker
(cd "$ROOT/fabric/chaincode/cityshield" && npm install --omit=dev)
(cd "$ROOT/fabric/gateway" && npm install --omit=dev)
(cd "$ROOT/dashboard" && npm install)
[ -f "$ROOT/multi/config.env" ] || cp "$ROOT/multi/config.env.example" "$ROOT/multi/config.env"
echo "D is ready. Edit multi/config.env, then run multi/start_D.sh"
