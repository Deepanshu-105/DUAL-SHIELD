#!/bin/bash
# A complete Hyperledger Fabric network on ONE machine (laptop D) without Docker:
#   1 or 3 orderers (Raft, ORDERERS=3), 2 peers (Org1 = target side, Org2 = peer side), channel "cityshield", chaincode "cityshield"
#   (chaincode-as-a-service, a Node process). Everything listens on 127.0.0.1; only the gateway (fabric/gateway) is exposed to the other laptops, over mutual TLS.
#
#   fabric/deploy/network.sh up        create crypto, start everything, create the channel, deploy + initialise the chaincode
#   fabric/deploy/network.sh down      stop all Fabric processes (keeps the ledger)
#   fabric/deploy/network.sh reset     stop and delete the whole network (ledger and keys)
#   fabric/deploy/network.sh status
# Endorsement policy: AND('Org1MSP.peer','Org2MSP.peer') - every transaction must be endorsed by both organisations.
set -u
FAB="$(cd "$(dirname "$0")/.." && pwd)"; DEP="$FAB/deploy"
BIN="${FABRIC_BIN:-$FAB/bin}"; NET="${NET_DIR:-$FAB/network}"
CC_DIR="$FAB/chaincode/cityshield"; CH=cityshield; CC=cityshield; CC_LABEL=cityshield_1; CC_PORT="${CC_PORT:-9999}"
ORDERERS="${ORDERERS:-1}"     # v11: 1 (default) or 3 Raft orderers (survives the loss of one); change only on a fresh network (reset first)
export PATH="$BIN:$PATH" FABRIC_CFG_PATH="$NET/cfg"
C="$NET/crypto"; OR="$C/ordererOrganizations/example.com"; O1="$C/peerOrganizations/org1.example.com"; O2="$C/peerOrganizations/org2.example.com"
ORDERER_CA="$OR/orderers/orderer.example.com/tls/ca.crt"

ord_name() { [ "$1" = 1 ] && echo orderer || echo "orderer$1"; }          # pid/log name
ord_host() { [ "$1" = 1 ] && echo orderer.example.com || echo "orderer$1.example.com"; }
ord_port() { echo $((7050 + ($1 - 1) * 10)); }
ord_admin() { echo $((7053 + ($1 - 1) * 10)); }

live_orderer() {   # echo "port host" of the first orderer that accepts connections (failover when one is down)
  local i
  for i in $(seq 1 "$ORDERERS"); do
    (exec 3<>/dev/tcp/127.0.0.1/$(ord_port $i)) 2>/dev/null && { echo "$(ord_port $i) $(ord_host $i)"; return; }
  done
  echo "7050 orderer.example.com"
}

die() { echo "FAIL: $*" >&2; exit 1; }
need() { [ -x "$BIN/$1" ] || die "$BIN/$1 missing: run fabric/deploy/install_fabric.sh"; }
org_env() {   # org_env 1|2 [admin|User1]: environment for the peer CLI acting as that identity
  local n=$1 who=${2:-Admin} O pp
  [ "$n" = 1 ] && { O=$O1; pp=7051; } || { O=$O2; pp=9051; }
  export CORE_PEER_TLS_ENABLED=true CORE_PEER_LOCALMSPID="Org${n}MSP" CORE_PEER_ADDRESS="127.0.0.1:$pp"
  export CORE_PEER_TLS_ROOTCERT_FILE="$O/peers/peer0.org$n.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$O/users/$who@org$n.example.com/msp"
}
start_proc() {  # name, then command with env already exported
  local name=$1; shift
  nohup "$@" > "$NET/logs/$name.log" 2>&1 &
  echo $! > "$NET/pids/$name.pid"
}

gen_crypto() {
  mkdir -p "$NET/cfg" "$NET/logs" "$NET/pids" "$NET/chaincode"
  cp "$DEP/configtx.yaml" "$NET/configtx.yaml"
  cp "$FAB/config/core.yaml" "$FAB/config/orderer.yaml" "$NET/cfg/"
  cp "$DEP/configtx.yaml" "$NET/cfg/"
  if [ "$ORDERERS" != 1 ] && [ ! -f "$NET/genesis.block" ]; then      # several orderers: rewrite endpoints and Raft consenters
    python3 - "$NET/configtx.yaml" "$NET/cfg/configtx.yaml" "$ORDERERS" <<'PY'
import re, sys
n = int(sys.argv[3])
ports = [7050 + 10 * i for i in range(n)]
hosts = ["orderer.example.com"] + ["orderer%d.example.com" % (i + 1) for i in range(1, n)]
for p in sys.argv[1:3]:
    t = open(p).read()
    t = re.sub(r'OrdererEndpoints: \[[^\]]*\]', 'OrdererEndpoints: [%s]' % ", ".join('"127.0.0.1:%d"' % x for x in ports), t)
    t = re.sub(r'Addresses: \["127.0.0.1:7050"\]', 'Addresses: [%s]' % ", ".join('"127.0.0.1:%d"' % x for x in ports), t)
    cons = "".join('      - Host: 127.0.0.1\n        Port: %d\n        ClientTLSCert: crypto/ordererOrganizations/example.com/orderers/%s/tls/server.crt\n        ServerTLSCert: crypto/ordererOrganizations/example.com/orderers/%s/tls/server.crt\n' % (x, h, h) for x, h in zip(ports, hosts))
    t = re.sub(r'(    Consenters:\n)(?:      - Host:.*\n        Port:.*\n        ClientTLSCert:.*\n        ServerTLSCert:.*\n)+', lambda m: m.group(1) + cons, t)
    open(p, "w").write(t)
PY
  fi
  # register the Chaincode-as-a-Service builder in the peers' core.yaml
  python3 - "$NET/cfg/core.yaml" "$DEP/ccaas_builder" <<'PY'
import re, sys
p, b = sys.argv[1], sys.argv[2]
lines = open(p).read().split("\n")
out, i = [], 0
while i < len(lines):
    ln = lines[i]
    out.append(ln)
    if re.match(r"^\s*externalBuilders:\s*(\[\])?\s*$", ln):
        ind = re.match(r"^(\s*)", ln).group(1)
        out[-1] = ind + "externalBuilders:"
        out += [ind + "  - name: ccaas_builder", ind + "    path: " + b, ind + "    propagateEnvironment:", ind + "      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG"]
        i += 1
        while i < len(lines) and re.match(r"^\s+(- |path:|propagateEnvironment:|name:)", lines[i]) and not lines[i].lstrip().startswith("#"):
            i += 1          # drop the sample entries that followed the empty list
        continue
    i += 1
open(p, "w").write("\n".join(out))
PY
  [ -d "$C" ] || { cp "$DEP/crypto-config.yaml" "$NET/crypto-config.yaml"; (cd "$NET" && cryptogen generate --config=crypto-config.yaml --output=crypto >/dev/null) || die "cryptogen"; }
  [ -f "$NET/genesis.block" ] || (cd "$NET" && FABRIC_CFG_PATH="$NET" configtxgen -profile CityShieldChannel -outputBlock genesis.block -channelID "$CH" >/dev/null 2>&1) || die "configtxgen"
}

start_orderer() {  # start_orderer [1|2|3]
  local i=${1:-1} h port adm d; h=$(ord_host $i); port=$(ord_port $i); adm=$(ord_admin $i)
  d="$NET/$(ord_name $i)"      # orderer 1 keeps the pre-v12 folder name "orderer" so an existing network keeps its ledger
  mkdir -p "$d"
  local T="$OR/orderers/$h/tls" M="$OR/orderers/$h/msp"
  (
    export ORDERER_GENERAL_LISTENADDRESS=127.0.0.1 ORDERER_GENERAL_LISTENPORT=$port ORDERER_GENERAL_LOCALMSPID=OrdererMSP ORDERER_GENERAL_LOCALMSPDIR="$M"
    export ORDERER_GENERAL_TLS_ENABLED=true ORDERER_GENERAL_TLS_PRIVATEKEY="$T/server.key" ORDERER_GENERAL_TLS_CERTIFICATE="$T/server.crt" ORDERER_GENERAL_TLS_ROOTCAS="[$T/ca.crt]"
    export ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE="$T/server.crt" ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY="$T/server.key" ORDERER_GENERAL_CLUSTER_ROOTCAS="[$T/ca.crt]"
    export ORDERER_GENERAL_BOOTSTRAPMETHOD=none ORDERER_CHANNELPARTICIPATION_ENABLED=true
    export ORDERER_ADMIN_TLS_ENABLED=true ORDERER_ADMIN_TLS_PRIVATEKEY="$T/server.key" ORDERER_ADMIN_TLS_CERTIFICATE="$T/server.crt" ORDERER_ADMIN_TLS_ROOTCAS="[$T/ca.crt]"
    export ORDERER_ADMIN_TLS_CLIENTROOTCAS="[$T/ca.crt]" ORDERER_ADMIN_LISTENADDRESS=127.0.0.1:$adm
    export ORDERER_FILELEDGER_LOCATION="$d/ledger" ORDERER_CONSENSUS_WALDIR="$d/wal" ORDERER_CONSENSUS_SNAPDIR="$d/snap"
    export ORDERER_OPERATIONS_LISTENADDRESS=127.0.0.1:$((8443 + i - 1)) ORDERER_GENERAL_GENESISPROFILE=CityShieldChannel
    start_proc "$(ord_name $i)" orderer
  )
}
start_peer() {  # start_peer 1|2
  local n=$1 O pp cp gp op
  [ "$n" = 1 ] && { O=$O1; pp=7051; cp=7052; gp=9051; op=9444; } || { O=$O2; pp=9051; cp=9052; gp=7051; op=9445; }
  local P="$O/peers/peer0.org$n.example.com"
  mkdir -p "$NET/peer$n"
  (
    export CORE_PEER_ID="peer0.org$n.example.com" CORE_PEER_ADDRESS="127.0.0.1:$pp" CORE_PEER_LISTENADDRESS="127.0.0.1:$pp" CORE_PEER_CHAINCODELISTENADDRESS="127.0.0.1:$cp"
    export CORE_PEER_GOSSIP_BOOTSTRAP="127.0.0.1:$gp" CORE_PEER_GOSSIP_EXTERNALENDPOINT="127.0.0.1:$pp" CORE_PEER_LOCALMSPID="Org${n}MSP" CORE_PEER_MSPCONFIGPATH="$P/msp"
    export CORE_PEER_TLS_ENABLED=true CORE_PEER_TLS_CERT_FILE="$P/tls/server.crt" CORE_PEER_TLS_KEY_FILE="$P/tls/server.key" CORE_PEER_TLS_ROOTCERT_FILE="$P/tls/ca.crt"
    export CORE_PEER_FILESYSTEMPATH="$NET/peer$n/data" CORE_OPERATIONS_LISTENADDRESS="127.0.0.1:$op" CORE_LEDGER_STATE_STATEDATABASE=goleveldb CORE_LEDGER_SNAPSHOTS_ROOTDIR="$NET/peer$n/snapshots"
    export CORE_PEER_GOSSIP_USELEADERELECTION=true CORE_PEER_GOSSIP_ORGLEADER=false
    start_proc peer$n peer node start
  )
}
wait_port() { for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.5; done; die "port $1 did not open (see $NET/logs)"; }

join_orderer() {  # join_orderer [1|2|3]
  local i=${1:-1} adm h; adm=$(ord_admin $i); h=$(ord_host $i)
  local ca="$OR/orderers/$h/tls/ca.crt"
  osnadmin channel list -o 127.0.0.1:$adm --ca-file "$ca" --client-cert "$OR/users/Admin@example.com/tls/client.crt" --client-key "$OR/users/Admin@example.com/tls/client.key" 2>/dev/null | grep -q "\"$CH\"" && return 0
  osnadmin channel join --channelID "$CH" --config-block "$NET/genesis.block" -o 127.0.0.1:$adm --ca-file "$ca" \
    --client-cert "$OR/users/Admin@example.com/tls/client.crt" --client-key "$OR/users/Admin@example.com/tls/client.key" >/dev/null || die "osnadmin join (orderer $i)"
}
join_peers() {
  for n in 1 2; do
    org_env $n
    peer channel list 2>/dev/null | grep -q "^$CH" || peer channel join -b "$NET/genesis.block" >/dev/null 2>&1 || die "peer$n join"
  done
}

package_cc() {
  [ -f "$NET/chaincode/$CC.tgz" ] && return 0
  local W; W=$(mktemp -d)
  printf '{"address":"127.0.0.1:%s","dial_timeout":"10s","tls_required":false}' "$CC_PORT" > "$W/connection.json"
  printf '{"type":"ccaas","label":"%s"}' "$CC_LABEL" > "$W/metadata.json"
  (cd "$W" && tar czf code.tar.gz connection.json && tar czf "$NET/chaincode/$CC.tgz" metadata.json code.tar.gz)
  rm -rf "$W"
}
pkg_id() { org_env 1; peer lifecycle chaincode queryinstalled 2>/dev/null | sed -n "s/^Package ID: \(${CC_LABEL}:[0-9a-f]*\),.*/\1/p" | head -1; }
start_cc() {
  local id; id=$(pkg_id); [ -n "$id" ] || die "chaincode package not installed"
  pkill -f "fabric-chaincode-node server" 2>/dev/null
  [ -d "$CC_DIR/node_modules" ] || (cd "$CC_DIR" && npm install --silent --no-audit --no-fund) || die "npm install (chaincode)"
  (cd "$CC_DIR" && CHAINCODE_SERVER_ADDRESS="127.0.0.1:$CC_PORT" CHAINCODE_ID="$id" nohup npx fabric-chaincode-node server --chaincode-address="127.0.0.1:$CC_PORT" --chaincode-id="$id" > "$NET/logs/chaincode.log" 2>&1 & echo $! > "$NET/pids/chaincode.pid")
  wait_port "$CC_PORT"
}
deploy_cc() {
  package_cc
  for n in 1 2; do org_env $n; peer lifecycle chaincode install "$NET/chaincode/$CC.tgz" >/dev/null 2>&1; done
  local id; id=$(pkg_id); [ -n "$id" ] || die "install failed"
  start_cc
  org_env 1
  peer lifecycle chaincode querycommitted --channelID "$CH" --name "$CC" 2>/dev/null | grep -q "Version: 1.0" && return 0   # restart of an existing network
  local lo; lo=($(live_orderer)); local ord=(-o 127.0.0.1:${lo[0]} --ordererTLSHostnameOverride ${lo[1]} --tls --cafile "$ORDERER_CA")
  for n in 1 2; do
    org_env $n
    peer lifecycle chaincode approveformyorg "${ord[@]}" --channelID "$CH" --name "$CC" --version 1.0 --package-id "$id" --sequence 1 \
      --signature-policy "AND('Org1MSP.peer','Org2MSP.peer')" >/dev/null 2>&1 || true
  done
  sleep 2
  org_env 1
  peer lifecycle chaincode checkcommitreadiness --channelID "$CH" --name "$CC" --version 1.0 --sequence 1 --signature-policy "AND('Org1MSP.peer','Org2MSP.peer')" 2>/dev/null | grep -q "Org2MSP: true" || die "org approvals missing"
  peer lifecycle chaincode querycommitted --channelID "$CH" --name "$CC" 2>/dev/null | grep -q "Version: 1.0" || \
  peer lifecycle chaincode commit "${ord[@]}" --channelID "$CH" --name "$CC" --version 1.0 --sequence 1 --signature-policy "AND('Org1MSP.peer','Org2MSP.peer')" \
    --peerAddresses 127.0.0.1:7051 --tlsRootCertFiles "$O1/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses 127.0.0.1:9051 --tlsRootCertFiles "$O2/peers/peer0.org2.example.com/tls/ca.crt" >/dev/null 2>&1 || die "commit failed (see $NET/logs)"
}
invoke() {  # invoke <json> : as Org1 Admin, endorsed by both orgs
  org_env 1
  local lo; lo=($(live_orderer)); peer chaincode invoke -o 127.0.0.1:${lo[0]} --ordererTLSHostnameOverride ${lo[1]} --tls --cafile "$ORDERER_CA" -C "$CH" -n "$CC" -c "$1" --waitForEvent \
    --peerAddresses 127.0.0.1:7051 --tlsRootCertFiles "$O1/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses 127.0.0.1:9051 --tlsRootCertFiles "$O2/peers/peer0.org2.example.com/tls/ca.crt" 2>&1
}
query() { org_env 1; peer chaincode query -C "$CH" -n "$CC" -c "$1" 2>&1; }

up() {
  need peer; need orderer; need configtxgen; need cryptogen; need osnadmin
  gen_crypto
  for i in $(seq 1 "$ORDERERS"); do
    n=$(ord_name $i)
    { [ -f "$NET/pids/$n.pid" ] && kill -0 "$(cat "$NET/pids/$n.pid")" 2>/dev/null; } || start_orderer $i
  done
  for i in $(seq 1 "$ORDERERS"); do wait_port "$(ord_port $i)"; wait_port "$(ord_admin $i)"; done
  for i in $(seq 1 "$ORDERERS"); do join_orderer $i; done
  [ "$ORDERERS" -gt 1 ] && sleep 4          # Raft election
  [ -f "$NET/pids/peer1.pid" ] && kill -0 "$(cat "$NET/pids/peer1.pid")" 2>/dev/null || start_peer 1
  [ -f "$NET/pids/peer2.pid" ] && kill -0 "$(cat "$NET/pids/peer2.pid")" 2>/dev/null || start_peer 2
  wait_port 7051; wait_port 9051
  sleep 2
  join_peers
  sleep 2
  deploy_cc
  query '{"function":"params","Args":[]}' | grep -q "not initialised" && { invoke '{"function":"initLedger","Args":[]}' | grep -q "status:200" || die "initLedger failed"; }
  echo "FABRIC_UP channel=$CH chaincode=$CC owner=$(query '{"function":"params","Args":[]}' | sed 's/.*"owner":"\([^"]*\)".*/\1/')"
}
down() {
  for f in "$NET"/pids/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; done
  pkill -f "fabric-chaincode-node server" 2>/dev/null; echo FABRIC_DOWN
}
status() {
  for f in orderer orderer2 orderer3 peer1 peer2 chaincode; do
    [ -f "$NET/pids/$f.pid" ] || continue
    if [ -f "$NET/pids/$f.pid" ] && kill -0 "$(cat "$NET/pids/$f.pid")" 2>/dev/null; then echo "$f: running"; else echo "$f: stopped"; fi
  done
  query '{"function":"params","Args":[]}' 2>&1 | tail -1
}
case "${1:-}" in
  up) up ;;
  down) down ;;
  reset) down; rm -rf "$NET"; echo FABRIC_RESET ;;
  status) status ;;
  invoke) invoke "$2" ;;
  query) query "$2" ;;
  stop-orderer) kill "$(cat "$NET/pids/$(ord_name "${2:-1}").pid")" && echo "orderer ${2:-1} stopped" ;;      # for failover tests
  start-orderer) start_orderer "${2:-1}" && echo "orderer ${2:-1} started" ;;
  *) echo "usage: $0 up|down|reset|status|stop-orderer N|start-orderer N"; exit 1 ;;
esac
