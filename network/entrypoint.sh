#!/bin/bash
set -e

# Firewall rule is lost whenever this container is recreated; rebuild it every start.
ipset create city_blacklist hash:ip -exist
if ! iptables -C INPUT -m set --match-set city_blacklist src -j DROP 2>/dev/null; then
  iptables -I INPUT -m set --match-set city_blacklist src -j DROP
fi

exec python3 /opt/shield/listener.py
