#!/usr/bin/env bash
# Dual-Shield host hardening for Linux (run as root).  ./harden_linux.sh [apply|undo|status] [--dry-run]
#   1) DDoS floor on THIS host: SYN cookies, bigger backlog, rp_filter, per-source connection / SYN-rate limits (own chain DUALSHIELD_RL)
#   2) tamper resistance: code + config made immutable (chattr +i) so even a root-owned script cannot silently edit them,
#      and systemd units with Restart=always so killing the guard/listener restarts it within seconds
# Honest limit: root can still `chattr -i`, unload rules or stop systemd. This raises the cost and makes tampering LOUD (it
# needs an extra privileged step that auditd / the chain can log); it does not make a rooted host trustworthy.
set -u
ACT="${1:-status}"; DRY=0; [ "${2:-}" = "--dry-run" ] || [ "${1:-}" = "--dry-run" ] && DRY=1
[ "$ACT" = "--dry-run" ] && ACT=status
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SYN_RATE="${SYN_RATE:-50/second}"; SYN_BURST="${SYN_BURST:-100}"; CONN_MAX="${CONN_MAX:-100}"
PORTS="${PROTECT_PORTS:-22,80,443,8600}"
UNITDIR="${UNITDIR:-/etc/systemd/system}"
run() { if [ "$DRY" = 1 ]; then echo "DRY: $*"; else "$@" 2>/dev/null || echo "  (failed: $*)"; fi; }
[ "$DRY" = 0 ] && [ "$(id -u)" != 0 ] && { echo "run as root (or use --dry-run)"; exit 1; }

unit() {  # unit <name> <exec> <workdir>
  local f="$UNITDIR/dualshield-$1.service"
  local body="[Unit]
Description=Dual-Shield $1
After=network.target
[Service]
WorkingDirectory=$3
EnvironmentFile=-$ROOT/multi/config.env
ExecStart=$2
Restart=always
RestartSec=2
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target"
  if [ "$DRY" = 1 ]; then echo "DRY: write $f"; else printf '%s\n' "$body" > "$f"; fi
}

apply() {
  echo "== DDoS floor"
  run sysctl -w net.ipv4.tcp_syncookies=1 net.ipv4.tcp_max_syn_backlog=4096 net.ipv4.conf.all.rp_filter=1 net.ipv4.icmp_ignore_bogus_error_responses=1 net.core.somaxconn=4096
  run iptables -N DUALSHIELD_RL
  run iptables -F DUALSHIELD_RL
  run iptables -A DUALSHIELD_RL -p tcp --syn -m hashlimit --hashlimit-name ds_syn --hashlimit-mode srcip --hashlimit-above "$SYN_RATE" --hashlimit-burst "$SYN_BURST" -j DROP
  run iptables -A DUALSHIELD_RL -p tcp -m multiport --dports "$PORTS" -m connlimit --connlimit-above "$CONN_MAX" --connlimit-mask 32 -j REJECT --reject-with tcp-reset
  run iptables -A DUALSHIELD_RL -j RETURN
  iptables -C INPUT -j DUALSHIELD_RL 2>/dev/null || run iptables -I INPUT 1 -j DUALSHIELD_RL
  echo "== tamper resistance"
  for f in "$ROOT"/detector/*.py "$ROOT"/network/*.py "$ROOT"/ransomware/*.py "$ROOT"/multi/*.py "$ROOT"/multi/*.sh "$ROOT/multi/config.env"; do
    [ -f "$f" ] && run chattr +i "$f"
  done
  unit guard "$(command -v python3 || echo /usr/bin/python3) $ROOT/ransomware/guard.py" "$ROOT/ransomware"
  unit listener "$(command -v python3 || echo /usr/bin/python3) $ROOT/network/listener.py" "$ROOT"
  unit ssh-parser "$(command -v python3 || echo /usr/bin/python3) $ROOT/detector/ssh_parser.py" "$ROOT"
  run systemctl daemon-reload
  for s in guard listener ssh-parser; do run systemctl enable --now dualshield-$s; done
  echo "done. To edit code later:  $0 undo"
}
undo() {
  for f in "$ROOT"/detector/*.py "$ROOT"/network/*.py "$ROOT"/ransomware/*.py "$ROOT"/multi/*.py "$ROOT"/multi/*.sh "$ROOT/multi/config.env"; do [ -f "$f" ] && run chattr -i "$f"; done
  run iptables -D INPUT -j DUALSHIELD_RL; run iptables -F DUALSHIELD_RL; run iptables -X DUALSHIELD_RL
  for s in guard listener ssh-parser; do run systemctl disable --now dualshield-$s; run rm -f "$UNITDIR/dualshield-$s.service"; done
  echo "undone"
}
status() {
  iptables -S DUALSHIELD_RL 2>/dev/null | head -5 || echo "no DDoS chain"
  lsattr "$ROOT/multi/config.env" 2>/dev/null
  systemctl is-active dualshield-guard dualshield-listener dualshield-ssh-parser 2>/dev/null
}
case "$ACT" in apply) apply ;; undo) undo ;; status) status ;; *) echo "usage: $0 apply|undo|status [--dry-run]"; exit 1 ;; esac
