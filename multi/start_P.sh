#!/bin/bash
# Laptop P (peer). Run with sudo, AFTER start_D.sh. Stays in the foreground and shows peer blocks.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
need_root; need_venv
pkill -f network/listener.py 2>/dev/null; pkill -f multi/agent.py 2>/dev/null
ipset create city_blacklist hash:ip -exist
ipset flush city_blacklist
iptables -C INPUT -m set --match-set city_blacklist src -j DROP 2>/dev/null || \
  iptables -I INPUT -m set --match-set city_blacklist src -j DROP
: > /var/log/peer_block.log

fetch_deploy || { echo "FAIL: cannot fetch the contract from http://$D_IP:3000 (is start_D.sh running?)"; exit 1; }
ROLE=peer SHIELD_ROOT="$ROOT" SHIELD_PY="$PY" nohup "$PY" "$ROOT/multi/agent.py" > /var/log/agent.out 2>&1 &
echo "P READY: agent on :8800, listening to the chain at $CHAIN_HTTP. Peer log below (Ctrl+C stops it)."
echo "-----"
exec env CHAIN_HTTP="$CHAIN_HTTP" DEPLOY="$ROOT/deployments/localhost.json" "$PY" -u "$ROOT/network/listener.py"
