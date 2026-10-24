# sourced by the other multi/*.sh scripts
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/multi/config.env"
if [ ! -f "$CFG" ]; then
  echo "Missing multi/config.env. Run:  cp multi/config.env.example multi/config.env   then edit the four IPs."
  exit 1
fi
. "$CFG"
export AGENT_TOKEN
export CHAIN_HTTP="http://$D_IP:8545"
VENV="$ROOT/blockchain/.venv"
PY="$VENV/bin/python3"
need_root() { [ "$EUID" -eq 0 ] || { echo "Run this with sudo:  sudo $0"; exit 1; }; }
need_venv() { [ -x "$PY" ] || { echo "Python environment missing. Run the install script for this laptop first."; exit 1; }; }
fetch_deploy() {   # contract address + ABI come from the dashboard laptop
  for i in $(seq 1 30); do
    curl -sf "http://$D_IP:3000/localhost.json" -o "$ROOT/deployments/localhost.json" && return 0
    sleep 2
  done
  return 1
}
