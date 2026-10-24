#!/bin/bash
# Laptop P (peer). Run with sudo.
set -e
[ "$EUID" -eq 0 ] || { echo "Run with sudo:  sudo $0"; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
apt-get update -qq
apt-get install -y ipset iptables iproute2 procps curl git python3 python3-venv python3-pip
python3 -m venv "$ROOT/blockchain/.venv"
"$ROOT/blockchain/.venv/bin/pip" install -q web3
[ -f "$ROOT/multi/config.env" ] || cp "$ROOT/multi/config.env.example" "$ROOT/multi/config.env"
echo "P is ready. Edit multi/config.env, then run:  sudo multi/start_P.sh"
