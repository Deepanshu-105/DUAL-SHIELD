#!/bin/bash
# Laptop T (target). Run with sudo, AFTER start_D.sh. Stays in the foreground and shows the parser log.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
need_root; need_venv
[ ${#AGENT_SECRET_T} -ge 16 ] || { echo "AGENT_SECRET_T missing in multi/config.env (run multi/gen_secrets.sh on D)"; exit 1; }
export PATH="$VENV/bin:$PATH"
pkill -f multi/join.py 2>/dev/null
resolve_peers target

pkill -f ssh_parser.py 2>/dev/null; pkill -f flood_detector.py 2>/dev/null; pkill -f expire_blocks.py 2>/dev/null; pkill -f login_watch.py 2>/dev/null; pkill -f arp_watch.py 2>/dev/null; pkill -f multi/agent.py 2>/dev/null
service ssh start 2>/dev/null || service sshd start
service rsyslog start
touch /var/log/auth.log
ipset create city_blacklist hash:ip -exist
# v13.15: a restart (or a crash an attacker caused on purpose) must not erase the blocks and the evidence.
# PRODUCTION=1 or KEEP_BLOCKS=1: blocks are restored from /var/lib/dualshield/blocklist.save and logs are appended, not emptied.
KEEP="${KEEP_BLOCKS:-${PRODUCTION:-0}}"; SAVE=/var/lib/dualshield/blocklist.save; mkdir -p /var/lib/dualshield; chmod 700 /var/lib/dualshield
if [ "$KEEP" = "1" ]; then
  touch /var/log/parser_block.log /var/log/metrics.log
  pkill -f multi/blockkeeper.py 2>/dev/null
  "$PY" "$ROOT/multi/blockkeeper.py" --restore --once          # journal (written BEFORE every block) -> firewall: a hard crash loses nothing
  nohup "$PY" -u "$ROOT/multi/blockkeeper.py" > /var/log/blockkeeper.out 2>&1 &     # restores blocks removed behind our back, logs BLOCKKEEPER_TAMPER
else
  ipset flush city_blacklist
  : > /var/log/parser_block.log; : > /var/log/metrics.log
fi

wait_gateway || { echo "FAIL: cannot reach the Fabric gateway at $D_IP:$GATEWAY_PORT (is start_D.sh running? TLS settings and certificates the same?)"; exit 1; }
PYTHONPATH="$ROOT/network" "$PY" "$ROOT/network/chain_setup.py" --register 1 || { echo "FAIL: node registration on Fabric"; exit 1; }

"$ROOT/ransomware/setup_sample.sh" >/dev/null 2>&1 || echo "WARN: sample setup failed"
: > "$ROOT/ransomware/evidence/watch.log"
COREPORT="${GATEWAY_LAB:-1}" PYTHONPATH="$ROOT/network" \
  "$PY" "$ROOT/network/chain_report.py" 203.0.113.1 >/dev/null 2>&1 || true      # warm-up report
"$ROOT/blockchain/scripts/anchor_clean.sh" "$A_IP" >/dev/null 2>&1 || echo "WARN: clean-state anchor failed (rollback will say ANCHOR_MISSING)"

pkill -f multi/node_watch.py 2>/dev/null
[ -s /var/lib/dualshield/nodewatch.baseline.json ] || "$PY" "$ROOT/multi/node_watch.py" --init      # baseline = this (clean) node
nohup "$PY" -u "$ROOT/multi/node_watch.py" > /var/log/nodewatch.out 2>&1 &     # NODEWATCH_ALERT lines: new port / uid-0 / keys / cron / module ...
AGENT_ALLOW_V=""; [ "${PRODUCTION:-0}" = "1" ] && AGENT_ALLOW_V="$D_IP,127.0.0.1"      # v13.15: only the dashboard laptop may even talk to the agent
AGENT_DEMO="${AGENT_DEMO:-0}" PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW="${AGENT_ALLOW:-$AGENT_ALLOW_V}" CONTAIN_ALLOW="$D_IP,$P_IP" CONTAIN="${CONTAIN:-}" QUARANTINE_MAX_S="${QUARANTINE_MAX_S:-900}" AGENT_SECRET="$AGENT_SECRET_T" ROLE=target SHIELD_ROOT="$ROOT" SHIELD_PY="$PY" nohup "$PY" "$ROOT/multi/agent.py" > /var/log/agent.out 2>&1 &
# v3: opt-in in the lab (FLOOD=1 ...), ON by default when PRODUCTION=1 (v13.15)
if [ "${PRODUCTION:-0}" = "1" ]; then FLOOD="${FLOOD:-1}"; LOGIN_WATCH="${LOGIN_WATCH:-1}"; ARP_WATCH="${ARP_WATCH:-1}"; fi
# v3, opt-in (FLOOD=1 / BLOCK_TTL=seconds in multi/config.env): DDoS and port-scan detector, and block expiry.
if [ "${FLOOD:-0}" = "1" ]; then
  [ "$KEEP" = "1" ] && touch /var/log/flood_block.log || : > /var/log/flood_block.log
  nohup env COREPORT="${GATEWAY_LAB:-1}" PYTHONPATH="$ROOT/network" WHITELIST_EXTRA="$D_IP,$P_IP" \
    "$PY" -u "$ROOT/detector/flood_detector.py" > /var/log/flood.out 2>&1 &
  echo "flood detector started (log /var/log/flood.out)"
fi
if [ "${LOGIN_WATCH:-0}" = "1" ]; then
  [ "$KEEP" = "1" ] && touch /var/log/login_block.log || : > /var/log/login_block.log
  nohup env PYTHONPATH="$ROOT/network" COREPORT="${GATEWAY_LAB:-1}" WHITELIST_EXTRA="$D_IP,$P_IP" \
    "$PY" -u "$ROOT/detector/login_watch.py" > /var/log/login_watch.out 2>&1 &
  echo "login watch started (slow brute force, stolen logins)"
fi
if [ "${ARP_WATCH:-0}" = "1" ]; then
  [ "$KEEP" = "1" ] && touch /var/log/arp_alert.log || : > /var/log/arp_alert.log
  nohup env PYTHONPATH="$ROOT/network" WHITELIST_EXTRA="$D_IP,$P_IP" \
    "$PY" -u "$ROOT/detector/arp_watch.py" > /var/log/arp_watch.out 2>&1 &
  echo "ARP watch started"
fi
if [ "${BLOCK_TTL:-0}" -gt 0 ] 2>/dev/null; then
  nohup "$PY" -u "$ROOT/detector/expire_blocks.py" --ttl "$BLOCK_TTL" > /var/log/expire.out 2>&1 &
  echo "block expiry on: $BLOCK_TTL s"
fi
# v13.20: more attacks. web_guard (SQLi/XSS/traversal/RCE/scanners/flood + restore of defaced files, quarantine of web shells), host_guard (reverse shells, miners).
# ON by default with PRODUCTION=1; in the lab: WEB_GUARD=1 / HOST_GUARD=1 in multi/config.env. WEB_LOG = nginx/apache access log, WEB_ROOT = web folder.
pkill -f detector/web_guard.py 2>/dev/null; pkill -f detector/host_guard.py 2>/dev/null
if [ "${WEB_GUARD:-${PRODUCTION:-0}}" = "1" ]; then
  WEB_LOG_V="${WEB_LOG:-$(ls /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null | head -1)}"
  [ -d "${WEB_ROOT:-/var/www/html}" ] && [ ! -d /var/lib/dualshield/web_snapshot ] && "$PY" "$ROOT/detector/web_guard.py" --snapshot
  nohup env WEB_LOG="$WEB_LOG_V" WHITELIST_EXTRA="$D_IP,$P_IP" "$PY" -u "$ROOT/detector/web_guard.py" > /var/log/web_guard.out 2>&1 &
  echo "web guard started (log ${WEB_LOG_V:-none found}, snapshot of ${WEB_ROOT:-/var/www/html})"
fi
if [ "${HOST_GUARD:-${PRODUCTION:-0}}" = "1" ]; then
  nohup env WHITELIST_EXTRA="$D_IP,$P_IP" "$PY" -u "$ROOT/detector/host_guard.py" > /var/log/host_guard.out 2>&1 &
  echo "host guard started (reverse shells, miners)"
fi
echo "T READY: agent on :8800, SSH on :22, protecting against $A_IP. Parser log below (Ctrl+C stops it)."
echo "-----"
cd "$ROOT/detector"
exec env COREPORT="${GATEWAY_LAB:-1}" PYTHONPATH="$ROOT/network" \
  WHITELIST_EXTRA="$D_IP,$P_IP" TOR_LIST="$ROOT/detector/tor_exit_nodes.txt" \
  TOR_LIST_EXTRA="$ROOT/detector/tor_lab_test.txt" "$PY" -u ssh_parser.py
