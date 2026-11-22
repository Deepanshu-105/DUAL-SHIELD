#!/bin/bash
# Laptop P (peer). Run with sudo, AFTER start_D.sh. Stays in the foreground and shows peer blocks.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
need_root; need_venv
[ ${#AGENT_SECRET_P} -ge 16 ] || { echo "AGENT_SECRET_P missing in multi/config.env (run multi/gen_secrets.sh on D)"; exit 1; }
pkill -f network/listener.py 2>/dev/null; pkill -f multi/join.py 2>/dev/null
[ "$T_IP" = "$P_IP" ] || pkill -f expire_blocks.py 2>/dev/null          # same laptop: leave T's expiry job alone
[ -f /var/run/ds_agent_peer.pid ] && kill "$(cat /var/run/ds_agent_peer.pid)" 2>/dev/null   # only P's own agent
resolve_peers peer
ipset create city_blacklist hash:ip -exist
if [ "${KEEP_BLOCKS:-${PRODUCTION:-0}}" = "1" ]; then
  pkill -f multi/blockkeeper.py 2>/dev/null
  "$PY" "$ROOT/multi/blockkeeper.py" --restore --once
  nohup "$PY" -u "$ROOT/multi/blockkeeper.py" > /var/log/blockkeeper.out 2>&1 &
else
  ipset flush city_blacklist
fi
iptables -C INPUT -m set --match-set city_blacklist src -j DROP 2>/dev/null || \
  iptables -I INPUT -m set --match-set city_blacklist src -j DROP
: > /var/log/peer_block.log

wait_gateway || { echo "FAIL: cannot reach the Fabric gateway at $D_IP:$GATEWAY_PORT (is start_D.sh running? TLS settings and certificates the same?)"; exit 1; }
PYTHONPATH="$ROOT/network" "$PY" "$ROOT/network/chain_setup.py" --register 2 || { echo "FAIL: node registration on Fabric"; exit 1; }
AGENT_PORT="${P_AGENT_PORT:-8800}" pkill -f multi/node_watch.py 2>/dev/null
[ -s /var/lib/dualshield/nodewatch.baseline.json ] || "$PY" "$ROOT/multi/node_watch.py" --init      # baseline = this (clean) node
nohup "$PY" -u "$ROOT/multi/node_watch.py" > /var/log/nodewatch.out 2>&1 &     # NODEWATCH_ALERT lines: new port / uid-0 / keys / cron / module ...
# v13.20: more attacks. web_guard (SQLi/XSS/traversal/RCE/scanners/flood + restore of defaced files, quarantine of web shells), host_guard (reverse shells, miners).
# ON by default with PRODUCTION=1; in the lab: WEB_GUARD=1 / HOST_GUARD=1 in multi/config.env. WEB_LOG = nginx/apache access log, WEB_ROOT = web folder.
pkill -f detector/web_guard.py 2>/dev/null; pkill -f detector/host_guard.py 2>/dev/null
if [ "${HOST_GUARD:-${PRODUCTION:-0}}" = "1" ]; then
  nohup env WHITELIST_EXTRA="$D_IP,$T_IP" "$PY" -u "$ROOT/detector/host_guard.py" > /var/log/host_guard.out 2>&1 &
fi
PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW="${AGENT_ALLOW:-$([ "${PRODUCTION:-0}" = "1" ] && echo "$D_IP,127.0.0.1")}" AGENT_SECRET="$AGENT_SECRET_P" ROLE=peer SHIELD_ROOT="$ROOT" SHIELD_PY="$PY" nohup "$PY" "$ROOT/multi/agent.py" > /var/log/agent_peer.out 2>&1 &
echo $! > /var/run/ds_agent_peer.pid
if [ "${PEER_DETECT:-0}" = "1" ]; then
  # v11: P also guards its own SSH and reports what IT sees as node 2: a real second reporter (needed when GATEWAY_LAB=0)
  service ssh start 2>/dev/null || service sshd start; service rsyslog start; touch /var/log/auth.log
  : > /var/log/parser_block.log; : > /var/log/metrics.log
  nohup env NODE_ID=2 PYTHONPATH="$ROOT/network" WHITELIST_EXTRA="$D_IP,$T_IP" TOR_LIST="$ROOT/detector/tor_exit_nodes.txt" \
    "$PY" -u "$ROOT/detector/ssh_parser.py" > /var/log/peer_parser.out 2>&1 &
  echo "P also detects SSH attacks and reports as node 2 (log /var/log/peer_parser.out)"
fi
if [ "${BLOCK_TTL:-0}" -gt 0 ] 2>/dev/null && [ "$T_IP" != "$P_IP" ]; then
  nohup "$PY" -u "$ROOT/detector/expire_blocks.py" --ttl "$BLOCK_TTL" > /var/log/expire.out 2>&1 &
  echo "block expiry on: $BLOCK_TTL s"
fi
echo "P READY: agent on :${P_AGENT_PORT:-8800}, listening to Fabric through the gateway at $D_IP:$GATEWAY_PORT. Peer log below (Ctrl+C stops it)."
echo "-----"
exec env PYTHONPATH="$ROOT/network" "$PY" -u "$ROOT/network/listener.py"
