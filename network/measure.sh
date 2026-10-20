#!/bin/bash
echo "run,ip,seconds"
for i in $(seq 1 10); do
  IP=203.0.113.$((100 + i))
  T0=$(docker exec -e COREPORT=1 target python3 /opt/shield/chain_report.py $IP --block | grep TARGET_BLOCK | sed 's/.*ts=//')
  sleep 3
  T1=$(docker exec peer grep "ip=$IP " /var/log/peer_block.log | tail -1 | sed 's/.*ts=//')
  echo "$i,$IP,$(awk "BEGIN{printf \"%.3f\", $T1 - $T0}")"
done
