# Dual-Shield

Two-layer defence demo, built as a student project.

- **Layer 1: network defence + blockchain.** An SSH log parser blocks brute-force sources in milliseconds
  (`ipset`). The block is reported to a smart contract (CityShield). When 2 of the registered nodes report the
  same IP, the contract emits a consensus event and the peer node blocks it too (immunisation).
- **Layer 2: ransomware detection and recovery.** A file watcher flags files whose header or entropy changed,
  kills the process after 3 distinct files in 2 s, and rolls back from a clean snapshot. Before restoring,
  the snapshot's Merkle root is checked against the root stored on the chain, so a tampered snapshot is refused.
- **Dashboard.** Live view of both layers, a rollback button, an event timeline and the measured numbers.

Everything runs in an isolated lab on one machine (Docker network 172.30.0.0/24). The ransomware is a mock
(`ransomware/mock_crypto.py`) that only touches copies. Never point any of this at a real network or real files.

## What you need
Ubuntu (WSL2 on Windows works), Docker with Compose, Node.js 20, Python 3.10 or newer, git.
Internet access is needed on the first run (Docker images and `apt`).

## First-time setup (once)
```bash
git clone https://github.com/Deepanshu-105/DUAL-SHIELD.git
cd DUAL-SHIELD

# Python for the blockchain scripts
python3 -m venv blockchain/.venv
blockchain/.venv/bin/pip install web3

# Python for the ransomware demo (outside any virtualenv)
pip install watchdog cryptography      # add --break-system-packages if pip asks for it

# Node packages
(cd blockchain && npm install)
(cd dashboard && npm install)
```

## Run the demo
1. **Start the lab** (Hardhat chain, contract, three containers, clean snapshot anchored on-chain):
   ```bash
   ./start_lab.sh
   ```
   Expected: `LAB READY` and no `WARN` line. The demo files in `ransomware/data/` are created automatically.
2. **Start the dashboard** in another terminal:
   ```bash
   cd dashboard && npm run dev
   ```
   Open http://localhost:3000. Both layer pills are green.
3. **Run the end-to-end demo** from the repository folder:
   ```bash
   ./demo.sh
   ```
   Stages: attack by mock ransomware, block, immunise the peer, kill, rollback.
   Expected: `PASS peer blocked ... in ~1300 to 2000 ms`, `KILLED`, `ROLLBACK_OK 10 of 10`, `flagged files: 3`, `kills: 1`.
4. Reload the dashboard: both pills are red. Click **Roll back to clean state**: the box shows
   `ANCHOR_MATCH` and `ROLLBACK_OK`.

A real brute-force run from the attacker container:
```bash
docker exec attacker hydra -l testuser -P /root/pw.txt -t 4 ssh://172.30.0.10
docker exec target ipset list city_blacklist      # 172.30.0.12 is now blocked
```

## Tests and measurements
```bash
(cd blockchain && npx hardhat test)               # 6 passing
(cd blockchain && npx hardhat run scripts/gas_report.js)
docker exec target python3 /root/detector/bench.py 10
bash network/real_runs.sh 5
bash detector/test_whitelist.sh
```

## Results (frozen)
| File | Contents |
|---|---|
| `network/LATENCY_TABLE.md` | Latency and gas table with sources |
| `ransomware/RESULTS_FROZEN.md` | Detection, kill, rollback and false-positive results, with limits |
| `blockchain/REPORT_DRAFT.md` | Blockchain design, gas, latency, poisoning test |
| `network/LOG_FORMATS.md` | Log formats used by the dashboard |
| `docs/screens/` | Dashboard screenshots of the three demo states |

## Known limits
- Local chain with instant mining: no real block time or network delay.
- The second chain report in the demo is simulated (`COREPORT=1`), because the lab has one real detector.
- Benign edits that rewrite a file's header (for example editing the top of a file) are flagged by check A.
  One flag does not kill anything; the kill rule needs 3 distinct files in 2 s.
- New files with no baseline, and files that were already random or compressed, are not checked by check B.
- The first chain report after a fresh start is slower (cold start); `start_lab.sh` warms it up.

## Troubleshooting
- `peer` cannot start or shows listener errors: run `./start_lab.sh` again (it recreates the peer).
- `ANCHOR_MISSING` on rollback: the chain was redeployed; run `blockchain/scripts/anchor_clean.sh`.
- `python modules missing` in `demo.sh`: leave any `(.venv)` with `deactivate`, then `pip install watchdog cryptography`.
- Never truncate `/var/log/auth.log` in the target while the parser is running.

## Team
M1 network defence, M2 blockchain, M3 ransomware detection and recovery, M4 dashboard and integration.
