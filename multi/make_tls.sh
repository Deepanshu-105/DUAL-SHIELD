#!/bin/bash
# Run ONCE on D. Creates a private certificate authority and one certificate per laptop role (mutual TLS).
#   multi/make_tls.sh            writes multi/tls/{ca.crt, ca.key, dashboard|target|peer/{ca.crt,node.crt,node.key}}
# Then copy ONLY multi/tls/target/ to T and multi/tls/peer/ to P (as multi/tls/node/ on that laptop, e.g. with scp),
# and keep multi/tls/dashboard/ on D. Never copy ca.key anywhere; keep it offline after issuing.
# Each certificate's CN names its role ("dualshield-target", ...): a laptop is accepted only for the role on its cert.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TLS_BOOTSTRAP=1   # certificates do not exist yet: do not insist on them
. "$ROOT/multi/common.sh"
OUT="${TLS_DIR:-$ROOT/multi/tls}"; DAYS="${TLS_DAYS:-365}"
mkdir -p "$OUT"; chmod 700 "$OUT"; cd "$OUT" || exit 1
umask 077
if [ ! -f ca.key ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -keyout ca.key -out ca.crt -days 1825 -subj "/CN=Dual-Shield private CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null || exit 1
  echo "created CA (ca.key stays on D)"
fi
issue() {   # issue role extra-SAN
  local role=$1 san="DNS:localhost,IP:127.0.0.1${2:+,$2}"
  mkdir -p "$role"
  openssl req -newkey rsa:3072 -nodes -keyout "$role/node.key" -out "$role/node.csr" -subj "/CN=dualshield-$role" 2>/dev/null || return 1
  printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\n" "$san" > "$role/ext.cnf"
  openssl x509 -req -in "$role/node.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$role/node.crt" -days "$DAYS" -extfile "$role/ext.cnf" 2>/dev/null || return 1
  cp ca.crt "$role/ca.crt"; rm -f "$role/node.csr" "$role/ext.cnf"; chmod 600 "$role/node.key"
  echo "issued $role (valid $DAYS days)"
}
if [ "$1" = "--node" ]; then          # v13.12: certificate for a node added later (network/add_node.py NAME ORG); CN dualshield-node-NAME lets the gateway give it exactly that identity
  [[ "$2" =~ ^[A-Za-z][A-Za-z0-9]{1,15}$ ]] || { echo "usage: multi/make_tls.sh --node NAME   (letters and digits)"; exit 1; }
  [ -f ca.key ] || { echo "no CA here: run multi/make_tls.sh first"; exit 1; }
  issue "node-$2" ""; echo "copy multi/tls/node-$2 -> that laptop as multi/tls/node"; exit 0
fi
# re-running this script (without --node) ROTATES the three role certificates; the CA is kept, so nothing else changes. Copy the new target/ and peer/ folders again.
issue dashboard "${D_IP:+IP:$D_IP}"
issue target "${T_IP:+IP:$T_IP}"
issue peer "${P_IP:+IP:$P_IP}"
echo "copy multi/tls/target -> T:multi/tls/node   and   multi/tls/peer -> P:multi/tls/node   (D uses multi/tls/dashboard)"
