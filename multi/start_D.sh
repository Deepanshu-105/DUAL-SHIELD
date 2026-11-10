#!/bin/bash
# Laptop D: start Hyperledger Fabric (network, chaincode, gateway), then run the dashboard (stays in the foreground).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
LOGD="$ROOT/multi/logs"; mkdir -p "$LOGD"
[ ${#DASH_PASS} -ge 8 ] && [ ${#AGENT_SECRET_T} -ge 16 ] && [ ${#AGENT_SECRET_P} -ge 16 ] || { echo "Set DASH_PASS, AGENT_SECRET_T and AGENT_SECRET_P in multi/config.env (run multi/gen_secrets.sh)"; exit 1; }
# ---- Hyperledger Fabric (no gas): network, chaincode, gateway
FAB="$ROOT/fabric"
[ -x "$FAB/bin/peer" ] || { echo "Fabric tools missing. Run once:  multi/install_D.sh   (or fabric/deploy/install_fabric.sh)"; exit 1; }
[ -d "$FAB/chaincode/cityshield/node_modules" ] && [ -d "$FAB/gateway/node_modules" ] || { echo "Node packages missing. Run multi/install_D.sh"; exit 1; }
echo "starting Hyperledger Fabric (orderer, Org1 peer, Org2 peer, chaincode cityshield) ..."
"$FAB/deploy/network.sh" up || { echo "FAIL: Fabric network did not start (see fabric/network/logs)"; exit 1; }
pkill -f "fabric/gateway/server.js" 2>/dev/null; sleep 1
GW_ENV="GATEWAY_PORT=$GATEWAY_PORT GATEWAY_HOST=0.0.0.0"
[ "${TLS:-0}" = "1" ] && GW_ENV="$GW_ENV GATEWAY_TLS=1 TLS_DIR=$ROOT/multi/tls/dashboard"
# GATEWAY_LAB=1 (default): any authenticated laptop may use any Fabric identity, so the demo target can report "as the peer" and reach K=2.
# GATEWAY_LAB=0: each certificate may use only its own identity (needs a second reporter on P; not part of the demo yet).
GW_ENV="$GW_ENV GATEWAY_LAB=${GATEWAY_LAB:-1}"
nohup env $GW_ENV node "$FAB/gateway/server.js" > $LOGD/fabric_gateway.out 2>&1 &
export TLS_DIR="${TLS_DIR:-$ROOT/multi/tls/dashboard}"
export GATEWAY_URL="$([ "${TLS:-0}" = "1" ] && echo https || echo http)://127.0.0.1:$GATEWAY_PORT"
wait_gateway || { echo "FAIL: Fabric gateway not answering (see $LOGD/fabric_gateway.out)"; exit 1; }
PYTHONPATH="$ROOT/network" python3 "$ROOT/network/chain_setup.py" --approve || { echo "FAIL: node approval"; exit 1; }
unset GATEWAY_URL
cd "$ROOT"
echo
echo "Chain:     Hyperledger Fabric channel cityshield (no gas). Gateway on :$GATEWAY_PORT ($([ "${TLS:-0}" = "1" ] && echo "mutual TLS" || echo "plain HTTP"), lab identities: GATEWAY_LAB=${GATEWAY_LAB:-1})"
echo "           run sudo multi/lockdown.sh D so only T and P can reach the gateway"
echo "Dashboard: http://localhost:3000   sign in with DASH_PASS (administrator) or DASH_VIEW_PASS (read-only viewer)"
echo "Now start T and P (sudo multi/start_T.sh, sudo multi/start_P.sh). Dashboard starting ..."
if [ "${TLS:-0}" = "1" ]; then
  pkill -f tls_proxy.py 2>/dev/null
  nohup python3 -u "$ROOT/multi/tls_proxy.py" server --listen 0.0.0.0:3443 --to 127.0.0.1:3000 --no-client-cert > $LOGD/tls_dash.out 2>&1 &
  echo "TLS on: gateway only via mutual TLS on :$GATEWAY_PORT, dashboard at https://$D_IP:3443 (trust multi/tls/dashboard/ca.crt in your browser)"
fi
if [ "${DISCOVERY:-0}" = "1" ]; then
  pkill -f multi/registry.py 2>/dev/null
  nohup env AGENT_SECRET_T="$AGENT_SECRET_T" AGENT_SECRET_P="$AGENT_SECRET_P" REGISTRY_PORT="${REGISTRY_PORT:-8801}" python3 -u "$ROOT/multi/registry.py" > $LOGD/registry.out 2>&1 &
  echo "Registry:  :${REGISTRY_PORT:-8801}   (T and P find each other through it; log $LOGD/registry.out)"
fi
SCHEME=http; [ "${TLS:-0}" = "1" ] && SCHEME=https
cd "$ROOT/dashboard"
GATEWAY_PORT="$GATEWAY_PORT" DISCOVERY="${DISCOVERY:-0}" TLS="${TLS:-0}" MULTI=1 TARGET_AGENT="$SCHEME://$T_IP:8800" PEER_AGENT="$SCHEME://$P_IP:8800" ATTACKER_IP="$A_IP" \
  bash -c 'HOST="$([ "${TLS:-0}" = "1" ] && echo 127.0.0.1 || echo 0.0.0.0)"
    if [ "${DASH_DEV:-0}" = "1" ]; then exec npm run dev -- -H "$HOST"; fi
    # production build: no development server, no source maps in the browser, live data never cached
    npm run build >"'"$LOGD"'/dashboard_build.out" 2>&1 || { echo "dashboard build failed, see '"$LOGD"'/dashboard_build.out"; exit 1; }
    exec npm run start -- -H "$HOST" -p 3000' 
