#!/bin/bash
# N real Hydra attacks: drop_ms plus the first packet actually dropped (packet-level).
N=${1:-5}
cd "$(dirname "$0")"
docker cp probe.py attacker:/root/probe.py
printf "wrong1\nwrong2\nwrong3\nwrong4\nwrong5\n" > /tmp/pw5.txt
docker cp /tmp/pw5.txt attacker:/root/pw.txt
: > /tmp/real_rows.csv
echo "run,drop_ms,block_to_first_dropped_probe_ms,total_ms"
for i in $(seq 1 $N); do
  docker exec attacker pkill -f probe.py 2>/dev/null
  docker exec target pkill -f ssh_parser.py 2>/dev/null
  docker exec target ipset flush city_blacklist
  docker exec target sh -c ": > /var/log/metrics.log; : > /var/log/parser_block.log; : > /var/log/parser.out"
  docker exec -d target sh -c "cd /root/detector && python3 -u ssh_parser.py >> /var/log/parser.out 2>&1"
  sleep 4
  docker exec -d attacker sh -c "python3 /root/probe.py 16 > /root/probe.log"
  sleep 1
  docker exec attacker timeout 14 hydra -l testuser -P /root/pw.txt -t 4 ssh://172.30.0.10 > /dev/null 2>&1
  sleep 2
  docker exec attacker pkill -f probe.py 2>/dev/null
  sleep 1
  docker exec attacker cat /root/probe.log > /tmp/probe_$i.log
  D=$(docker exec target grep drop_ms /var/log/metrics.log | tail -1 | sed 's/.*=//')
  TB=$(docker exec target grep "ip=172.30.0.12 " /var/log/parser_block.log | tail -1 | sed 's/.*ts=//')
  if [ -z "$D" ] || [ -z "$TB" ]; then echo "$i,NO_BLOCK_LOGGED,,"; continue; fi
  FF=$(awk -v tb="$TB" '$2==0 && $1>=tb-0.5 {print $1; exit}' /tmp/probe_$i.log)
  if [ -z "$FF" ]; then echo "$i,$D,NO_DROPPED_PROBE,"; continue; fi
  awk -v i=$i -v d="$D" -v tb="$TB" -v ff="$FF" 'BEGIN{g=(ff-tb)*1000; printf "%d,%.2f,%.1f,%.1f\n", i, d, g, d+g}' | tee -a /tmp/real_rows.csv
done
docker exec target ipset flush city_blacklist
awk -F, '{n++; d+=$2; g+=$3; t+=$4; if($4>m)m=$4} END{if(n) printf "REAL RUNS n=%d drop_avg=%.2f ms block_to_first_dropped_probe_avg=%.1f ms total_avg=%.1f ms total_max=%.1f ms (target <20)\n", n, d/n, g/n, t/n, m; else print "no complete runs"}' /tmp/real_rows.csv
