#!/bin/bash
# usage: network/block_immunise.sh IP
# Blocks IP on the target, reports it to the chain, and waits for the peer to block it.
ip="$1"
[ -z "$ip" ] && { echo "usage: $0 IP"; exit 2; }
t0=$(date +%s.%N)
docker exec -e COREPORT=1 target python3 /opt/shield/chain_report.py "$ip" --block >/dev/null \
  || { echo "FAIL: report to chain failed"; exit 1; }
for i in $(seq 1 120); do
  if docker exec peer ipset test city_blacklist "$ip" >/dev/null 2>&1; then
    t1=$(date +%s.%N)
    ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%d", (b-a)*1000}')
    if [ "$ms" -le 4000 ]; then echo "PASS peer blocked $ip in ${ms} ms"; exit 0
    else echo "FAIL too slow: ${ms} ms"; exit 1; fi
  fi
  sleep 0.05
done
echo "FAIL peer did not block $ip"; exit 1
