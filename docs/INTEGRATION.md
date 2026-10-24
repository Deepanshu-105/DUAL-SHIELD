# How the parts connect (M4)

## Data flow
1. SSH log (target:/var/log/auth.log) is read by detector/ssh_parser.py, which adds the IP to the ipset `city_blacklist`
   and writes target:/var/log/parser_block.log and metrics.log.
2. network/chain_report.py reports the IP to the CityShield contract (Hardhat chain, 127.0.0.1:8545).
3. The contract emits ThreatConsensusReached when 2 nodes reported the same IP.
4. The peer container (network/listener.py) polls the chain by block number, blocks the IP in its own ipset and writes
   peer:/var/log/peer_block.log.
5. The ransomware watcher (ransomware/detect.py watch --kill) writes ransomware/evidence/watch.log
   (FLAGGED, KILL_TRIGGER, KILLED lines).
6. A clean snapshot (ransomware/rollback.py snapshot) has its Merkle root anchored on the chain
   (blockchain/scripts/anchor_clean.sh). rollback.py restore --anchor IP refuses to restore if the root differs.

## Dashboard interfaces (dashboard/app)
| Endpoint | Reads | Used for |
|---|---|---|
| (browser, ethers) 127.0.0.1:8545 | contract events and tally, stakes | node cards, consensus tally |
| /api/detector | ransomware/evidence/watch.log | files flagged, kills |
| /api/blocked | docker exec ... ipset list city_blacklist (target, peer) | blocked IP tiles |
| /api/timeline | watch.log plus parser_block.log and peer_block.log | event timeline |
| POST /api/rollback | runs rollback.py restore --anchor | rollback button |
| /metrics.json (static) | dashboard/public/metrics.json | measured performance panel |
| /localhost.json (static) | copied from deployments/localhost.json by start_lab.sh | contract address and ABI |

Log formats: see network/LOG_FORMATS.md.

## Hidden from the dashboard
The warm-up report for 203.0.113.1 (sent by start_lab.sh) and the benchmark IPs 198.51.100.x are filtered out,
so the calm state is genuinely calm.
