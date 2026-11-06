#!/bin/bash
# Laptop P (peer). Run with sudo, AFTER start_D.sh. Stays in the foreground and shows peer blocks.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
need_root; need_venv
[ ${#AGENT_SECRET_P} -ge 16 ] || { echo "AGENT_SECRET_P missing in multi/config.env (run multi/gen_secrets.sh on D)"; exit 1; }
pkill -f network/listener.py 2>/dev/null; pkill -f expire_blocks.py 2>/dev/null; pkill -f multi/agent.py 2>/dev/null; pkill -f multi/join.py 2>/dev/null
resolve_peers peer
ipset create city_blacklist hash:ip -exist
ipset flush city_blacklist
iptables -C INPUT -m set --match-set city_blacklist src -j DROP 2>/dev/null || \
  iptables -I INPUT -m set --match-set city_blacklist src -j DROP
: > /var/log/peer_block.log

fetch_deploy || { echo "FAIL: cannot fetch the contract from http://$D_IP:3000 (is start_D.sh running?)"; exit 1; }
AGENT_SECRET="$AGENT_SECRET_P" ROLE=peer SHIELD_ROOT="$ROOT" SHIELD_PY="$PY" nohup "$PY" "$ROOT/multi/agent.py" > /var/log/agent.out 2>&1 &
if [ "${BLOCK_TTL:-0}" -gt 0 ] 2>/dev/null; then
  nohup "$PY" -u "$ROOT/detector/expire_blocks.py" --ttl "$BLOCK_TTL" > /var/log/expire.out 2>&1 &
  echo "block expiry on: $BLOCK_TTL s"
fi
echo "P READY: agent on :8800, listening to the chain at $CHAIN_HTTP. Peer log below (Ctrl+C stops it)."
echo "-----"
exec env CHAIN_HTTP="$CHAIN_HTTP" DEPLOY="$ROOT/deployments/localhost.json" "$PY" -u "$ROOT/network/listener.py"
