#!/usr/bin/env bash
# Extra hardening for T and P (Linux, run as root).   multi/harden_node.sh [apply|undo|status] [--dry-run] [--ssh-hardening] [--ssh-keys-only]
#  1) kernel settings   2) the agent port (8800) reachable ONLY from the dashboard laptop, at firewall level (before any code runs)
#  3) auditd rules that record changes to DualShield code/config, sshd_config, ld.so.preload, module loads, firewall tools
#  4) permissions of config and state   5) optional SSH hardening (never default: T's SSH is the bait for the brute-force demo)
# Everything is written to its own files, so `undo` removes exactly this.  --dry-run only prints.
set -u
ACT="apply"; DRY=0; SSHH=0; SSHK=0
for a in "$@"; do case "$a" in apply|undo|status) ACT="$a";; --dry-run) DRY=1;; --ssh-hardening) SSHH=1;; --ssh-keys-only) SSHH=1; SSHK=1;; esac; done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SYSCTL=/etc/sysctl.d/99-dualshield-node.conf; AUDIT=/etc/audit/rules.d/dualshield-node.rules; SSHD=/etc/ssh/sshd_config.d/99-dualshield.conf
CHAIN=DS_AGENT; PORT="${AGENT_PORT:-8800}"
cfgv() { grep -E "^[[:space:]]*(export[[:space:]]+)?$1=" "$ROOT/multi/config.env" 2>/dev/null | tail -1 | sed -E "s/^[^=]*=//; s/['\"]//g; s/[[:space:]]#.*//"; }
D_IP="${D_IP:-$(cfgv D_IP)}"
run() { if [ "$DRY" = 1 ]; then echo "DRY: $*"; else "$@" 2>/dev/null || echo "  (failed: $*)"; fi; }
put() { # put <file> <content>
  if [ "$DRY" = 1 ]; then echo "DRY: write $1"; printf '%s\n' "$2" | sed 's/^/     | /'; else mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; echo "  wrote $1"; fi; }
[ "$DRY" = 0 ] && [ "$(id -u)" != 0 ] && { echo "run as root (or use --dry-run)"; exit 1; }

apply() {
  echo "== 1) kernel settings"
  put "$SYSCTL" "kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_redirects = 0"
  run sysctl --system
  echo "== 2) agent port $PORT only from the dashboard laptop (${D_IP:-NOT SET})"
  if [ -z "$D_IP" ]; then echo "  skipped: D_IP not set in multi/config.env (never lock the agent without knowing D)";
  else
    run iptables -N $CHAIN; run iptables -F $CHAIN
    run iptables -A $CHAIN -s "$D_IP" -j RETURN
    run iptables -A $CHAIN -s 127.0.0.1 -j RETURN
    run iptables -A $CHAIN -j DROP
    if [ "$DRY" = 1 ]; then echo "DRY: iptables -I INPUT 1 -p tcp --dport $PORT -j $CHAIN (if not present)"; else
      iptables -C INPUT -p tcp --dport "$PORT" -j $CHAIN 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$PORT" -j $CHAIN; fi
  fi
  echo "== 3) audit rules"
  if [ "$DRY" = 1 ] || command -v auditctl >/dev/null; then
    put "$AUDIT" "-w $ROOT/multi -p wa -k ds_code
-w $ROOT/network -p wa -k ds_code
-w $ROOT/detector -p wa -k ds_code
-w $ROOT/ransomware -p wa -k ds_code
-w /etc/ssh/sshd_config -p wa -k ds_ssh
-w /etc/ld.so.preload -p wa -k ds_preload
-w /etc/sudoers -p wa -k ds_sudo
-w /etc/sudoers.d -p wa -k ds_sudo
-w /root/.ssh -p wa -k ds_keys
-w /sbin/ipset -p x -k ds_firewall
-w /usr/sbin/ipset -p x -k ds_firewall
-w /sbin/iptables -p x -k ds_firewall
-w /usr/sbin/iptables -p x -k ds_firewall
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k ds_modules"
    run augenrules --load
  else echo "  auditd not installed: sudo apt install auditd (rules skipped)"; fi
  echo "== 4) permissions"
  run chmod 600 "$ROOT/multi/config.env"; run mkdir -p /var/lib/dualshield; run chmod 700 /var/lib/dualshield
  echo "== 5) SSH"
  if [ "$SSHH" = 1 ]; then
    BODY="PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2"
    [ "$SSHK" = 1 ] && BODY="$BODY
PasswordAuthentication no
KbdInteractiveAuthentication no"
    put "$SSHD" "$BODY"
    if [ "$DRY" = 0 ]; then
      if command -v sshd >/dev/null && ! sshd -t 2>/dev/null; then rm -f "$SSHD"; echo "  sshd -t FAILED: SSH change removed again"; else (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null); fi
    fi
    [ "$SSHK" = 1 ] && echo "  keys only: make sure YOUR key is in ~/.ssh/authorized_keys BEFORE you log out"
  else echo "  not changed (T's SSH is the demo bait). Use --ssh-hardening, or --ssh-keys-only on P / a production T."; fi
  echo "done. Start the watcher: python3 multi/node_watch.py --init   (on a CLEAN node), then it runs from start_T.sh / start_P.sh"
}
undo() {
  echo "== undo"
  run rm -f "$SYSCTL" "$AUDIT" "$SSHD"
  run iptables -D INPUT -p tcp --dport "$PORT" -j $CHAIN; run iptables -F $CHAIN; run iptables -X $CHAIN
  run augenrules --load; run sysctl --system
  (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null) >/dev/null
}
status() {
  for f in "$SYSCTL" "$AUDIT" "$SSHD"; do [ -f "$f" ] && echo "ON   $f" || echo "off  $f"; done
  iptables -S $CHAIN >/dev/null 2>&1 && echo "ON   agent port firewall ($CHAIN)" || echo "off  agent port firewall"
  pgrep -f multi/node_watch.py >/dev/null && echo "ON   node_watch" || echo "off  node_watch"
}
case "$ACT" in apply) apply;; undo) undo;; status) status;; esac
