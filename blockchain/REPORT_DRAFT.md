# M2 Blockchain: report draft (Day 6)

## 1. Design
CityShield contract (Solidity 0.8, Hardhat local chain, ethers v6 / web3.py).
- Consensus: an IP is confirmed as a threat when K = 2 of N = 3 registered nodes report it.
- Registration: each node stakes 1 ether (`registerNode`).
- Poisoning defence: a report window of 60 s; if the second report does not arrive in time, `slashExpired(ip)` slashes the lone reporter's stake.
- Clean-state anchoring: `anchorCleanState(ip, merkleRoot, tAttack)` / `getCleanState(ip)` (per IP). The Merkle root comes from `ransomware/snapshot.py`.
- Events: ThreatReported, ThreatConsensusReached, NodeSlashed, CleanStateAnchored.

## 2. Gas per operation (measured)
| Operation | Gas |
|---|---|
| registerNode (stake 1 ETH, once per node) | 65,800 |
| reportThreat, first report for an IP | 164,381 to 164,393 |
| reportThreat, second report (consensus) | 113,409 to 113,421 |
| Whole consensus for one IP (two reports) | about 277,800 |
| slashExpired (lone reporter slashed) | 79,613 |
| anchorCleanState (per IP, 32-byte root) | 94,939 |
Fresh-chain figures are from `blockchain/gas_report.txt` (they vary by under 0.1% between runs).
Source: replay of Recon-PortScan (10 reports, gas_avg 164,382, max 164,393) and day 5 anchor tests.

## 3. Latency
- Chain confirmation per report: average 74.3 ms, max 148.7 ms (10 rows). Hardhat mines instantly, so this is not representative of a real network (stated in every result file).
- Report to peer block ("immunise", 10 runs, Day 5): 1,589 to 2,431 ms, mean 1,855 ms. Later runs after the warm-up fix: about 1.4 to 1.5 s. The first report after a fresh start is slow (cold start, 4.5 s) and is warmed up in start_lab.sh.

## 4. Poisoning resistance (poison_test.js)
- One lone report: count 1, K = 2, confirmed = false. A single node cannot blacklist an IP.
- After the window, `slashExpired` leaves the lone reporter with stake 0.

## 5. Dataset replay
Recon-PortScan and DictionaryBruteForce CSVs (CIC-IoT-2023 layout) replayed as chain reports with synthetic IPs (198.18.0.0/15). The dataset is used for load and gas only. Real detection comes from the SSH parser and the ransomware detector.

## 6. Clean-state anchoring and rollback
- The Merkle root of the clean snapshot is stored on-chain per IP.
- `verify_anchor.py` recomputes the root and compares. `rollback.py restore --anchor IP` refuses to restore when they differ.
- Test: clean snapshot gives ANCHOR_MATCH, restore of 10 of 10 files in 15 ms; a tampered snapshot gives ANCHOR_TAMPERED and RESTORE_REFUSED.

## 7. Limits (be honest in the demo)
- Local chain with instant mining; no real block time or network delay.
- The second node report is simulated (COREPORT=1) in the lab.
- `tAttack` is the time of the anchor call, not the exact attack start.
- Gas is reported in units, not currency; ether cost depends on the target chain.
- Gas figures come from `blockchain/scripts/gas_report.js` (fresh chain), plus the lab replay.
