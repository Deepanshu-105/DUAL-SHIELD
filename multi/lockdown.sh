#!/bin/bash
# v2: only the known laptops may reach the sensitive ports. Run with sudo on each laptop, after its start script
# (or before; the rules do not depend on the services running).
#   sudo multi/lockdown.sh D      Fabric gateway (8600) and dashboard 3000: only T and P (and D itself)
#   sudo multi/lockdown.sh T      agent 8800: only D          (SSH 22 stays open: that is what is defended)
#   sudo multi/lockdown.sh P      agent 8800: only D
#   sudo multi/lockdown.sh off    remove the rules
# Source addresses on a LAN can be spoofed by a determined attacker, so this narrows the door; it does not
# replace the signed requests, the approved-node contract and the dashboard login.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
need_root
ROLE="$1"
if [ "${DISCOVERY:-0}" = "1" ] && [ -f "$ROOT/multi/peers.json" ]; then   # fill T_IP / P_IP from the registry
  eval "$(python3 - "$ROOT/multi/peers.json" <<'PY'
import json, sys, time
d = json.load(open(sys.argv[1])); ttl = d.get("ttl", 120)
for role, key in (("target", "T_IP"), ("peer", "P_IP")):
    p = d.get("peers", {}).get(role)
    if p and time.time() - p["last"] <= 3 * ttl:
        print("%s=%s" % (key, p["ip"]))
PY
)"
fi
CH=DS_LOCK
iptables -D INPUT -j $CH 2>/dev/null
iptables -F $CH 2>/dev/null; iptables -X $CH 2>/dev/null
[ "$ROLE" = "off" ] && { echo "lockdown removed"; exit 0; }
iptables -N $CH || exit 1
guard() {   # guard PORT ip ip ... : accept those sources, drop everything else on that port
  local port=$1; shift
  for ip in "$@"; do iptables -A $CH -p tcp --dport "$port" -s "$ip" -j ACCEPT; done
  iptables -A $CH -p tcp --dport "$port" -j DROP
}
iptables -A $CH -i lo -j RETURN
case "$ROLE" in
  D) guard "${GATEWAY_PORT:-8600}" "$T_IP" "$P_IP" "$D_IP" 127.0.0.1    # Fabric gateway; orderer and peers listen on 127.0.0.1 only
     [ "${TLS:-0}" = "1" ] || guard 3000 "$T_IP" "$P_IP" "$D_IP" 127.0.0.1 ;;
  T|P) guard 8800 "$D_IP" ;;
  A) ;;
  *) echo "usage: sudo multi/lockdown.sh D|T|P|A|off"; iptables -X $CH; exit 1 ;;
esac
iptables -A $CH -j RETURN
iptables -I INPUT 1 -j $CH
echo "lockdown on for role $ROLE:"; iptables -S $CH
