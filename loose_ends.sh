#!/usr/bin/env bash
# Checks the m1-network branch and tests docker-compose. Run: bash loose_ends.sh
cd ~/DUAL-SHIELD || exit 1

echo "=============== 1. TEAMMATE BRANCH (origin/m1-network) ==============="
git fetch origin
echo "--- commits on m1-network that main does not have ---"
git log --format='%h %an: %s' main..origin/m1-network
echo "--- files changed on m1-network vs main ---"
git diff --stat main...origin/m1-network
echo "--- README section headings (look for duplicates) ---"
grep -n "^## " README.md

echo
echo "=============== 2. COMPOSE TEST ==============="
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
echo "using: $DC"

echo "--- removing hand-made containers ---"
docker rm -f target peer attacker

echo "--- removing old network that holds 172.30.0.0/24 ---"
for n in $(docker network ls --format '{{.Name}}'); do
  case "$n" in bridge|host|none) continue ;; esac
  if docker network inspect "$n" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | grep -q "172.30.0.0/24"; then
    docker network rm "$n" && echo "removed network: $n"
  fi
done

echo "--- starting lab ---"
$DC up -d || { echo "COMPOSE FAILED TO START"; exit 1; }

echo "--- waiting for target to finish installing (up to 3 min) ---"
for i in $(seq 1 36); do
  if docker exec target pgrep sshd >/dev/null 2>&1 && docker exec target pgrep rsyslogd >/dev/null 2>&1; then
    echo "target ready (sshd + rsyslogd running)"; break
  fi
  sleep 5
done

echo "--- results ---"
docker ps --format 'table {{.Names}}\t{{.Status}}'
echo -n "target sshd:     "; docker exec target pgrep sshd >/dev/null 2>&1 && echo OK || echo MISSING
echo -n "target rsyslogd: "; docker exec target pgrep rsyslogd >/dev/null 2>&1 && echo OK || echo MISSING
echo -n "target testuser: "; docker exec target id testuser >/dev/null 2>&1 && echo OK || echo MISSING
echo -n "target ipset:    "; docker exec target which ipset >/dev/null 2>&1 && echo OK || echo MISSING
echo -n "parser mounted:  "; docker exec target test -f /root/detector/ssh_parser.py && echo OK || echo MISSING
echo -n "attacker hydra:  "; docker exec attacker which hydra >/dev/null 2>&1 && echo OK || echo "NOT YET (still installing)"
echo -n "attacker->target ping: "; docker exec attacker ping -c 1 -W 2 172.30.0.10 >/dev/null 2>&1 && echo OK || echo FAIL
echo
echo "Paste everything above back to Claude."
