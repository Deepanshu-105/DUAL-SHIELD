# DualShield documentation (simple version)

## 1. The idea
- **Problem.** One machine that blocks attackers alone can be fooled (false alarms) or silenced (attacker with access). Ransomware encrypts files in seconds.
- **Layer 1.** The target detects an attacker and reports it to a Fabric chain. A block is applied only when K independent peers agree.
- **Layer 2.** A guard flags changed files, kills the process in milliseconds, cuts the network and restores files from a verified vault.
- **Dashboard.** One screen (and a phone) shows what was detected, blocked, killed and restored; alerts and a printable report.

## 2. Roles
| Role | Machine | Runs |
|---|---|---|
| A, A2 | attacker laptops | demo attacks only, aimed at T |
| T | target | SSH + web server, all guards, ransomware guard, vault, signed agent |
| P | peer | its own guards, listens to the chain, blocks confirmed attackers, signed agent |
| D | dashboard + chain | Fabric (CityShield chaincode), gateway :8600, `network/peer_trust.py`, dashboard :3000, alerts |

## 3. Layer 1 flow
1. A guard on T sees the attack (log line or traffic). 2. T reports the address to the chain through the gateway.
3. The chaincode counts reports from different organisations; at K (2 in the demo) the address is CONFIRMED.
4. T and P read the confirmed list and block the address; infrastructure addresses are never blocked; blocks can expire (`BLOCK_TTL`).
5. `peer_trust` scores peers; a peer that keeps reporting wrongly is overruled or suspended.
6. The block keeper restores a block that was removed behind our back (write-ahead journal).

## 4. Layer 2 flow
1. Baseline of the protected folder (headers, randomness) and a vault copy. 2. Check A: first bytes changed. Check B: a normally non-random file became random. A wiper test catches filler overwrite.
3. Kill rule: 3 distinct files in 2 s, process killed (about 2 ms in the lab), machine contained. 4. Restore from the vault with hash verification; decryptor lookup and shadow recovery as extras.
5. Types handled in the mock: crypto, wiper, double extortion, exfiltration (needs the exfil settings in `protect.json`), note-only.

## 5. Guards added in v13.14 to v13.23
| Guard | Catches | Does |
|---|---|---|
| Signed agent (`multi/agent.py`) | anyone calling T or P | accepts only signed, fresh requests from allowed addresses; lockout, size and time limits |
| `detector/web_guard.py` | SQLi, XSS, traversal, command injection, log4shell, probes, scanner tools, HTTP flood | scores log lines, blocks at 10 points in 60 s; restores defaced files; quarantines new web shells |
| `detector/host_guard.py` | reverse shells, crypto miners | scans processes, kills, blocks in and out, quarantines the file |
| `multi/node_watch.py` | new port, uid-0 account, SSH key, cron, kernel module | compares with a clean baseline, raises alerts |
| `multi/blockkeeper.py` | firewall block removed | restores it from the journal |
| `multi/harden_node.sh` | weak host settings | sysctl, iptables, auditd, SSH (run `--dry-run` first) |
| `multi/alert_notify.py` | serious events | Telegram / e-mail / webhook, flood-limited |

## 6. Dashboard
Tabs: Overview, Layer 1 Network, Attack events, Consensus and Chain, Governance, Layer 2 Ransomware, Security posture, Audit log. Roles: admin and read-only, TOTP, session timeout, every `/api` call needs a login, log text is escaped. The Attack events tab has an Incident report button (print or save as PDF).

## 7. Settings (`multi/config.env`, never commit it)
`D_IP T_IP P_IP A_IP`, `AGENT_SECRET_T/P`, `DASH_PASS`, `DASH_VIEW_PASS`, `PRODUCTION`, `WEB_GUARD`, `HOST_GUARD`, `LOGIN_WATCH`, `FLOOD`, `BLOCK_TTL`, `AGENT_DEMO`, `ALERT_*`, `DS_CHECK_A_ALLOW`. Every key is described in `multi/config.env.example`.

## 8. Tests and results
- `bash run_all_tests.sh`: 25 pass, 2 skip (they need the running chain). Mock ransomware: 10/10 killed, about 2 ms, rollback 10/10 hash match (`ransomware/RESULTS_FROZEN.md`).
- Check A false positives: 243/243 benign rewrites flagged (known weakness); opt-in allow-list about 2% (`ransomware/CHECK_A_ALLOWLIST.md`).
- Web/host guards, untuned held-out samples (`eval/results/*_BEFORE_TUNING.md`): SQLi 64 to 80%, XSS 87 to 92%, traversal 78 to 93%, command injection 57 to 97%, shells 85 to 88%, miners 88 to 92%. Samples were hand-written by the rule author; an independent set from a teammate (`eval/samples_teammate/`) is still to be added.

## 9. Limits
Root on T beats the guards; signature rules miss new styles; the lab chain is one machine with a supplied second report; ransomware tests are mock only; Windows is experimental.

## 10. Glossary
Chaincode = program on the chain. K of N = K independent peers must agree. Signed agent = small service on T and P that only accepts signed requests. Vault = verified copy of protected files. Quarantine = suspicious file moved out of reach (mode 000). Held-out = test samples not used to tune the rules.
