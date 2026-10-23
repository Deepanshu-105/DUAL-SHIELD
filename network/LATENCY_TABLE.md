# Dual-Shield: measured latency and cost (frozen Day 7)

All numbers are from this lab (Docker lab network, local Hardhat chain with instant mining).
Each row names the file the number comes from, so it can be re-run.

## Layer 1: network defence + chain

| Stage | Result | Runs | Target | Source |
|---|---|---|---|---|
| Lookup of an IP in the blacklist | 0.0015 to 0.0023 ms average | 10 | < 2 ms | network/day6_bench.txt |
| Local drop (3rd failed login to ipset add) | 1.9 to 3.9 ms average, max 7.8 ms | 10 | < 20 ms | network/day6_bench.txt |
| Real Hydra attack: drop | 2.0 ms average | 5 | < 20 ms | network/day6_real_runs.txt |
| Real Hydra attack: block to first dropped packet | 3.9 ms average | 5 | | network/day6_real_runs.txt |
| Real Hydra attack: total (drop + first dropped packet) | 5.9 ms average, max 8.3 ms | 5 | < 20 ms | network/day6_real_runs.txt |
| Chain confirmation of one report | 74 ms average, max 149 ms | 10 | | blockchain/day5_replay_portscan.txt |
| Report to peer blocked (immunisation) | 1,316 ms mean (1,224 to 1,572) | 5 | < 4,000 ms | network/day7_demo_runs.txt |

## Layer 2: ransomware recovery

| Stage | Result | Runs | Source |
|---|---|---|---|
| Kill signal after the kill rule fires | 70 to 221 microseconds (mean 116) | 5 | network/day7_demo_runs.txt |
| Restore of 10 files from the clean snapshot | 2.4 ms mean (2 to 3 ms) | 5 | network/day7_demo_runs.txt |
| Rollback button end to end (chain check + restore) | 859 ms | 1 | dashboard screenshot |
| Rollback refused when the snapshot is tampered | ANCHOR_TAMPERED, RESTORE_REFUSED | 1 | blockchain/day6_rollback_anchor.txt |

## Gas (units, fresh chain)

| Operation | Gas |
|---|---|
| registerNode (stake 1 ETH, once per node) | 65,800 |
| reportThreat, first report | 164,415 |
| reportThreat, second report (consensus) | 113,443 |
| slashExpired (lone reporter slashed) | 79,613 |
| anchorCleanState (per IP) | 94,949 |
Source: blockchain/gas_report.txt. Lab replay of 10 reports averaged 164,382 gas for the first report.

## What these numbers do not show (say so in the report)
- Local chain with instant mining: no real block time or network delay.
- The second chain report in the demo is simulated (COREPORT=1) because the lab has one real detector.
- Real Hydra attacks come from the attacker container on the lab network only.
- The first report after a fresh start is slower (cold start); start_lab.sh warms it up.
- Gas is in units, not money; ether cost depends on the target chain.
