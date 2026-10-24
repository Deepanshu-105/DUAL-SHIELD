#!/bin/bash
# Laptop A (attacker). Run with sudo for apt.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
sudo apt-get update -qq
sudo apt-get install -y hydra openssh-client curl git iputils-ping
[ -f "$ROOT/multi/config.env" ] || cp "$ROOT/multi/config.env.example" "$ROOT/multi/config.env"
echo "A is ready. Edit multi/config.env, then run multi/attack_A.sh when told to."
