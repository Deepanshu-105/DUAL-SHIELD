# Dual-Shield

A two-layer defence system built as a student project (team: Shivansh Tripathi, Deepanshu, Mayank Agarwal, Yash Yadav).

- **Layer 1, network defence on a blockchain.** Guards on the target (SSH, scan/flood, web, host, node watch) report an attacker to a
  Hyperledger Fabric chain (CityShield chaincode). A block is applied on the target and on the peer only when K independent nodes agree (K = 2 in the demo).
- **Layer 2, ransomware.** A guard flags changed files (header check + randomness check), kills the process after 3 distinct files in 2 s,
  cuts the machine off the network and restores every file from a verified vault.
- **Dashboard.** Live view of both layers, an Attack events tab, alerts to a phone (Telegram, e-mail, webhook) and a printable incident report.

The ransomware is a mock that only touches a sample folder. Run attacks only against your own machines. Never use real malware outside an isolated VM with the supervisor's written approval.

## Where to start
| You want to | Read |
|---|---|
| Understand the whole system (simple) | `docs/DOCUMENTATION.md` |
| Run the demo on 4 to 5 laptops + phones | `docs/DEMO_5_LAPTOPS_3_PHONES.md`, `multi/README_MULTI.md` |
| Run everything on one machine | "One-laptop lab" below |
| See what changed in each version | `docs/CHANGELOG.md`, `README_V13_*.md` |
| See the numbers and their limits | "Results" below |
| Final evidence run and checklist | `docs/FINAL_GUIDE.md` |

## What you need
Ubuntu or WSL2, Node.js 22, Python 3.10+, git. Docker only for the one-laptop lab. The ledger is Hyperledger Fabric 2.5 (no Hardhat, no gas; the `blockchain/` folder is a legacy prototype).

## First-time setup (once)
```bash
git clone https://github.com/Deepanshu-105/DUAL-SHIELD.git && cd DUAL-SHIELD
pip install watchdog cryptography        # add --break-system-packages if pip asks
fabric/deploy/install_fabric.sh          # Fabric 2.5 binaries, no Docker
(cd fabric/chaincode/cityshield && npm install)
(cd fabric/gateway && npm install --omit=dev)
(cd dashboard && npm install)
```

## One-laptop lab
```bash
./start_lab.sh                 # Fabric + 3 containers (target, peer, attacker); expect LAB READY
(cd dashboard && npm run dev)  # http://localhost:3000
./demo.sh                      # mock ransomware: block, immunise the peer, kill, rollback
```
Expected: `PASS peer blocked`, `KILLED`, `ROLLBACK_OK 10 of 10`, `flagged files: 3`, `kills: 1`.

## Multi-laptop run (D = dashboard + chain, T = target, P = peer, A = attacker)
```bash
bash multi/gen_secrets.sh                 # once, on D; then edit multi/config.env (never commit it)
multi/install_D.sh | sudo multi/install_T.sh | sudo multi/install_P.sh | multi/install_A.sh   # each on its own laptop
multi/start_D.sh ; sudo multi/start_T.sh ; sudo multi/start_P.sh      # in this order
multi/check_net.sh ; python3 multi/check_T.py                         # all green before the demo
```
Key settings in `multi/config.env` (full list in `multi/config.env.example`): `PRODUCTION`, `WEB_GUARD`, `HOST_GUARD`, `LOGIN_WATCH`, `FLOOD`,
`BLOCK_TTL`, `AGENT_DEMO` (demo ransomware button when PRODUCTION=1), `ALERT_*`, `DS_CHECK_A_ALLOW`.

## What it detects, blocks and recovers
| Attack | Detect and block | Recover |
|---|---|---|
| SSH brute force, slow spray, port scan, SYN/UDP flood, ARP spoof | Layer 1 detectors, chain consensus, ipset/iptables block on T and P | Blocks expire (`BLOCK_TTL`) and are restored if removed |
| Web: SQLi, XSS, traversal, command injection, log4shell, probes, scanners, HTTP flood | `web_guard` (score 10 in 60 s = block) | Defaced files restored from a clean snapshot; web shells quarantined |
| Reverse shell, crypto miner | `host_guard` (kill, block in and out) | File quarantined (mode 000), restorable |
| Host tampering (new port, uid 0, key, cron, module) | `node_watch` alerts, `harden_node.sh` | Baseline comparison |
| Ransomware: crypto, wiper, double extortion, exfiltration, note-only | Check A + B, kill rule, containment | Vault restore with hash check, decryptor lookup, shadow recovery |

## Tests
```bash
bash run_all_tests.sh          # all automated tests; SKIP = needs the running chain; exit 1 on any FAIL
python3 eval/eval_new_attacks.py ; python3 eval/heldout_round2.py samples_round3 round3    # offline evaluation of the web/host guards
python3 ransomware/test_m3.py  # 10 full mock-ransomware runs (slower)
```

## Results (what to quote, with limits)
| File | Contents |
|---|---|
| `ransomware/RESULTS_FROZEN.md` | Mock ransomware: 10/10 killed (about 2 ms), rollback 10/10 hash-identical; check A false positives |
| `ransomware/CHECK_A_ALLOWLIST.md` | Opt-in allow-list: benign flags 243/243 down to about 2%, with the measured trade-off |
| `eval/results/` | Web and host guard evaluation: untuned held-out numbers (`*_BEFORE_TUNING.md`) are the honest ones |
| `network/LATENCY_TABLE.md`, `blockchain/REPORT_DRAFT.md` | Latency, gas (legacy prototype) and poisoning test |
| `docs/screens/` | Dashboard screenshots |

## Known limits
- The chain in the lab is one machine; the second K = 2 report is supplied by T acting as a peer (`COREPORT=1` / `GATEWAY_LAB=1`) unless `PEER_DETECT=1`.
- An attacker with root on T can stop the guards or edit logs. The chain and the block journal limit the damage; they do not prevent it.
- Web and host detection is signature based. New styles pass until a rule is added (known misses: curl-pipe-bash droppers, Unicode traversal, REST filter injection).
- Check A flags benign operations that rewrite a file start (edit the top of a file, re-save a zip). One flag kills nothing (3 files in 2 s are needed). The allow-list is off by default.
- Files that were already random or compressed are not checked by check B. Ransomware tests are mock only.
- Windows support (`windows/`, ETW) is experimental and was tested with simulated commands.

## Troubleshooting
- Peer not starting: run `./start_lab.sh` again (recreates the peer).
- `ANCHOR_MISSING` on rollback: the chain was redeployed; run `blockchain/scripts/anchor_clean.sh`.
- Demo ransomware button returns 403: PRODUCTION=1 without `AGENT_DEMO=1` on T; restart T after setting it.
- Never truncate `/var/log/auth.log` on the target while the parser runs. Never commit `multi/config.env` (use `bash multi/push_to_github.sh`).

## Team
M1 network defence, M2 blockchain, M3 ransomware detection and recovery, M4 dashboard and integration.
