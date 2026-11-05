#!/bin/bash
# Host settings that blunt spoofed-source and SYN floods. Prints by default; --apply sets them; --undo restores.
#   sudo multi/harden_host.sh            show what would change
#   sudo multi/harden_host.sh --apply    apply (the old values are saved in /var/lib/dualshield_sysctl.bak)
#   sudo multi/harden_host.sh --undo
# Honest limit: this does not help against a flood that fills the network link (needs upstream filtering).
SETTINGS="net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 \
net.ipv4.conf.all.accept_source_route=0 net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.tcp_max_syn_backlog=4096 \
net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.log_martians=1"
BAK=/var/lib/dualshield_sysctl.bak
case "$1" in
  --apply)
    [ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
    mkdir -p /var/lib; [ -f "$BAK" ] || for s in $SETTINGS; do k=${s%%=*}; echo "$k=$(sysctl -n $k 2>/dev/null)"; done > "$BAK"
    for s in $SETTINGS; do sysctl -qw "$s" && echo "set $s"; done
    echo "HARDENED. Undo with: sudo $0 --undo" ;;
  --undo)
    [ -f "$BAK" ] || { echo "nothing to undo"; exit 0; }
    while read -r s; do sysctl -qw "$s" && echo "restored $s"; done < "$BAK"; rm -f "$BAK" ;;
  *)
    for s in $SETTINGS; do k=${s%%=*}; printf "%-45s now %-4s -> %s\n" "$k" "$(sysctl -n $k 2>/dev/null)" "${s##*=}"; done
    echo "(dry run: use --apply to change)" ;;
esac
