# sourced by the other multi/*.sh scripts
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/multi/config.env"
if [ ! -f "$CFG" ]; then
  echo "Missing multi/config.env. Run:  cp multi/config.env.example multi/config.env   then edit the four IPs."
  exit 1
fi
. "$CFG"
export TLS DISCOVERY REGISTRY_PORT AGENT_SECRET_T AGENT_SECRET_P DASH_PASS CHAIN_IP_KEY WHITELIST_CIDRS SELFGUARD_KEY
export CHAIN_HTTP="http://$D_IP:8545"
# v7 TLS=1: everything between laptops uses mutual TLS with certificates from the private CA (multi/make_tls.sh).
#   chain RPC  T,P -> local door 127.0.0.1:8545 -> TLS tunnel -> D:8546 -> chain (bound to 127.0.0.1 on D)
#   dashboard  operators use https://D_IP:3443 (password over TLS); T,P fetch the contract file over TLS
#   agents / registry speak mutual TLS themselves (multi/tlsutil.py)
TLSDIR="$ROOT/multi/tls/node"; [ -d "$ROOT/multi/tls/dashboard" ] && [ ! -d "$TLSDIR" ] && TLSDIR="$ROOT/multi/tls/dashboard"
if [ "${TLS:-0}" = "1" ] && [ "${TLS_BOOTSTRAP:-0}" != "1" ]; then
  [ -f "$TLSDIR/node.crt" ] && [ -f "$TLSDIR/node.key" ] && [ -f "$TLSDIR/ca.crt" ] || { echo "TLS=1 but no certificates in $TLSDIR. On D run: multi/make_tls.sh, then copy multi/tls/target (T) or multi/tls/peer (P) to multi/tls/node on that laptop."; exit 1; }
  export TLS TLS_DIR="$TLSDIR"
  export CHAIN_HTTP="http://127.0.0.1:8545"
fi
tls_chain_door() {   # T and P: plain local port that carries the chain RPC to D over mutual TLS
  [ "${TLS:-0}" = "1" ] || return 0
  pkill -f "tls_proxy.py client" 2>/dev/null
  nohup python3 -u "$ROOT/multi/tls_proxy.py" client --listen 127.0.0.1:8545 --to "$D_IP:8546" --expect dualshield-dashboard > /var/log/tls_chain.out 2>&1 &
  sleep 1
}
# v6 discovery (DISCOVERY=1): only D_IP is configured. T and P register with D and learn each other's address.
#   resolve_peers target|peer   registers this laptop, waits up to 60 s for the other one, fills T_IP / P_IP
resolve_peers() {
  [ "${DISCOVERY:-0}" = "1" ] || return 0
  local role="$1" secret
  [ "$role" = "target" ] && secret="$AGENT_SECRET_T" || secret="$AGENT_SECRET_P"
  ROLE="$role" AGENT_SECRET="$secret" D_IP="$D_IP" python3 "$ROOT/multi/join.py" --once --wait "${DISCOVERY_WAIT:-60}" || { echo "FAIL: cannot register with the dashboard laptop at $D_IP:${REGISTRY_PORT:-8801} (is start_D.sh running? same secret?)"; exit 1; }
  [ -f "$ROOT/multi/peers.env" ] && . "$ROOT/multi/peers.env"
  nohup env ROLE="$role" AGENT_SECRET="$secret" D_IP="$D_IP" python3 -u "$ROOT/multi/join.py" > /var/log/join.out 2>&1 &
  echo "discovery: T_IP=${T_IP:-?} P_IP=${P_IP:-?} (heartbeat to $D_IP every 30 s)"
}
VENV="$ROOT/blockchain/.venv"
PY="$VENV/bin/python3"
need_root() { [ "$EUID" -eq 0 ] || { echo "Run this with sudo:  sudo $0"; exit 1; }; }
need_venv() { [ -x "$PY" ] || { echo "Python environment missing. Run the install script for this laptop first."; exit 1; }; }
fetch_deploy() {   # contract address + ABI come from the dashboard laptop
  for i in $(seq 1 30); do
    if [ "${TLS:-0}" = "1" ]; then
      curl -sf --cacert "$TLS_DIR/ca.crt" "https://$D_IP:3443/localhost.json" -o "$ROOT/deployments/localhost.json" && return 0
    else
      curl -sf "http://$D_IP:3000/localhost.json" -o "$ROOT/deployments/localhost.json" && return 0
    fi
    sleep 2
  done
  return 1
}
