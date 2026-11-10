# sourced by the other multi/*.sh scripts
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/multi/config.env"
if [ ! -f "$CFG" ]; then
  echo "Missing multi/config.env. Run:  cp multi/config.env.example multi/config.env   then edit the four IPs."
  exit 1
fi
. "$CFG"
export T_AGENT_PORT P_AGENT_PORT DASH_VIEW_PASS DASH_SESSION_KEY DASH_IDLE_S DASH_MAX_S DEMO_MODE DASH_DEV TLS DISCOVERY REGISTRY_PORT AGENT_SECRET_T AGENT_SECRET_P DASH_PASS CHAIN_IP_KEY WHITELIST_CIDRS SELFGUARD_KEY
export GATEWAY_PORT="${GATEWAY_PORT:-8600}" GATEWAY_LAB D_IP
# v9: the chain is Hyperledger Fabric (no gas). T and P talk to the Fabric gateway on D: http://D_IP:GATEWAY_PORT, or with TLS=1
# https with mutual TLS (private CA, multi/make_tls.sh); the gateway lets each certificate use only its own Fabric identity.
# v7 TLS=1: everything between laptops uses mutual TLS with certificates from the private CA (multi/make_tls.sh).
#   Fabric gateway  T,P -> https://D_IP:8600 (mutual TLS; each certificate may use only its own Fabric identity)
#   dashboard  operators use https://D_IP:3443 (password over TLS); 
#   agents / registry speak mutual TLS themselves (multi/tlsutil.py)
TLSDIR="$ROOT/multi/tls/node"; [ -d "$ROOT/multi/tls/dashboard" ] && [ ! -d "$TLSDIR" ] && TLSDIR="$ROOT/multi/tls/dashboard"
if [ "${TLS:-0}" = "1" ] && [ "${TLS_BOOTSTRAP:-0}" != "1" ]; then
  [ -f "$TLSDIR/node.crt" ] && [ -f "$TLSDIR/node.key" ] && [ -f "$TLSDIR/ca.crt" ] || { echo "TLS=1 but no certificates in $TLSDIR. On D run: multi/make_tls.sh, then copy multi/tls/target (T) or multi/tls/peer (P) to multi/tls/node on that laptop."; exit 1; }
  export TLS TLS_DIR="$TLSDIR"
fi
wait_gateway() {   # T and P: the Fabric gateway on D must answer before we start
  for i in $(seq 1 40); do
    PYTHONPATH="$ROOT/network" "$PY" -c "from chainlib import Chain; Chain().head()" 2>/dev/null && return 0
    sleep 2
  done
  return 1
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
