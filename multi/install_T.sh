#!/bin/bash
# Laptop T (target). Run with sudo.
set -e
[ "$EUID" -eq 0 ] || { echo "Run with sudo:  sudo $0"; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
apt-get update -qq
apt-get install -y openssh-server rsyslog ipset iptables procps curl git python3 python3-venv python3-pip
python3 -m venv "$ROOT/blockchain/.venv"
"$ROOT/blockchain/.venv/bin/pip" install -q web3 watchdog cryptography
id testuser >/dev/null 2>&1 || useradd -m testuser
echo 'testuser:password123' | chpasswd
mkdir -p /etc/ssh/sshd_config.d
echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/00-lab.conf   # first value wins in sshd
ssh-keygen -A
[ -f "$ROOT/multi/config.env" ] || cp "$ROOT/multi/config.env.example" "$ROOT/multi/config.env"
echo "T is ready. Edit multi/config.env, then run:  sudo multi/start_T.sh"
