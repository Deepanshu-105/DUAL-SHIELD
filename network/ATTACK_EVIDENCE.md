# Real attack evidence (M1)

Attacker: Kali container (172.30.0.12) running Hydra against the target (172.30.0.10) over SSH, on the isolated lab network only.

Note on enrichment: the parser's Tor lookup uses the real exit list (1,209 addresses) plus detector/tor_lab_test.txt,
a lab-only test entry for the attacker container. The HASSH fingerprint was captured from Hydra in this lab. Neither is a public detection list.

## Source address seen by the target
M1 Day 6 source-IP check (real Hydra from attacker container to target)
Oct 23 10:23:25 2b8e39d62399 sshd[3520]: Failed password for testuser from 172.30.0.12 port 33384 ssh2
Oct 23 10:23:25 2b8e39d62399 sshd[3523]: Failed password for testuser from 172.30.0.12 port 33394 ssh2
Oct 23 10:23:25 2b8e39d62399 sshd[3521]: Failed password for testuser from 172.30.0.12 port 33392 ssh2
--- ipset city_blacklist:
Members:
172.30.0.12
--- parser_block.log:
PARSER_BLOCK ip=172.30.0.12 ts=1792751005.537

## Five real Hydra runs (drop and packet-level result)
run,drop_ms,block_to_first_dropped_probe_ms,total_ms
1,1.99,6.3,8.3
2,1.75,1.2,2.9
3,1.71,5.8,7.5
4,2.93,5.3,8.2
5,1.58,1.0,2.6
REAL RUNS n=5 drop_avg=1.99 ms block_to_first_dropped_probe_avg=3.9 ms total_avg=5.9 ms total_max=8.3 ms (target <20)

## Benchmark (10 runs)
RESULT runs=10 local_drop_avg=3.85 ms (max 7.80, target <20) lookup_avg=0.0023 ms (max 0.0045, target <2) tor_entries=1210 tor_load=3.0 ms
PASS
