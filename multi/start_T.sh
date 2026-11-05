#!/bin/bash
# Laptop T (target). Run with sudo, AFTER start_D.sh. Stays in the foreground and shows the parser log.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
need_root; need_venv
[ ${#AGENT_SECRET_T} -ge 16 ] || { echo "AGENT_SECRET_T missing in multi/config.env (run multi/gen_secrets.sh on D)"; exit 1; }
export PATH="$VENV/bin:$PATH"

pkill -f ssh_parser.py 2>/dev/null; pkill -f flood_detector.py 2>/dev/null; pkill -f expire_blocks.py 2>/dev/null; pkill -f login_watch.py 2>/dev/null; pkill -f arp_watch.py 2>/dev/null; pkill -f multi/agent.py 2>/dev/null
service ssh start 2>/dev/null || service sshd start
service rsyslog start
touch /var/log/auth.log
ipset create city_blacklist hash:ip -exist
ipset flush city_blacklist
: > /var/log/parser_block.log; : > /var/log/metrics.log

fetch_deploy || { echo "FAIL: cannot fetch the contract from http://$D_IP:3000 (is start_D.sh running?)"; exit 1; }
curl -sf -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "$CHAIN_HTTP" | grep -q result || { echo "FAIL: chain not reachable at $CHAIN_HTTP"; exit 1; }

"$ROOT/ransomware/setup_sample.sh" >/dev/null 2>&1 || echo "WARN: sample setup failed"
: > "$ROOT/ransomware/evidence/watch.log"
COREPORT=1 PYTHONPATH="$ROOT/network" DEPLOY="$ROOT/deployments/localhost.json" \
  "$PY" "$ROOT/network/chain_report.py" 203.0.113.1 >/dev/null 2>&1 || true      # warm-up report
"$ROOT/blockchain/scripts/anchor_clean.sh" "$A_IP" >/dev/null 2>&1 || echo "WARN: clean-state anchor failed (rollback will say ANCHOR_MISSING)"

AGENT_SECRET="$AGENT_SECRET_T" ROLE=target SHIELD_ROOT="$ROOT" SHIELD_PY="$PY" nohup "$PY" "$ROOT/multi/agent.py" > /var/log/agent.out 2>&1 &
# v3, opt-in (FLOOD=1 / BLOCK_TTL=seconds in multi/config.env): DDoS and port-scan detector, and block expiry.
if [ "${FLOOD:-0}" = "1" ]; then
  : > /var/log/flood_block.log
  nohup env COREPORT=1 PYTHONPATH="$ROOT/network" DEPLOY="$ROOT/deployments/localhost.json" WHITELIST_EXTRA="$D_IP,$P_IP" \
    "$PY" -u "$ROOT/detector/flood_detector.py" > /var/log/flood.out 2>&1 &
  echo "flood detector started (log /var/log/flood.out)"
fi
if [ "${LOGIN_WATCH:-0}" = "1" ]; then
  : > /var/log/login_block.log
  nohup env PYTHONPATH="$ROOT/network" DEPLOY="$ROOT/deployments/localhost.json" COREPORT=1 WHITELIST_EXTRA="$D_IP,$P_IP" \
    "$PY" -u "$ROOT/detector/login_watch.py" > /var/log/login_watch.out 2>&1 &
  echo "login watch started (slow brute force, stolen logins)"
fi
if [ "${ARP_WATCH:-0}" = "1" ]; then
  : > /var/log/arp_alert.log
  nohup env PYTHONPATH="$ROOT/network" DEPLOY="$ROOT/deployments/localhost.json" WHITELIST_EXTRA="$D_IP,$P_IP" \
    "$PY" -u "$ROOT/detector/arp_watch.py" > /var/log/arp_watch.out 2>&1 &
  echo "ARP watch started"
fi
if [ "${BLOCK_TTL:-0}" -gt 0 ] 2>/dev/null; then
  nohup "$PY" -u "$ROOT/detector/expire_blocks.py" --ttl "$BLOCK_TTL" > /var/log/expire.out 2>&1 &
  echo "block expiry on: $BLOCK_TTL s"
fi
echo "T READY: agent on :8800, SSH on :22, protecting against $A_IP. Parser log below (Ctrl+C stops it)."
echo "-----"
cd "$ROOT/detector"
exec env COREPORT=1 PYTHONPATH="$ROOT/network" DEPLOY="$ROOT/deployments/localhost.json" \
  WHITELIST_EXTRA="$D_IP,$P_IP" TOR_LIST="$ROOT/detector/tor_exit_nodes.txt" \
  TOR_LIST_EXTRA="$ROOT/detector/tor_lab_test.txt" "$PY" -u ssh_parser.py
