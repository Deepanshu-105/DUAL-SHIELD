# Dual-Shield v5 — closing the real-world gaps

Nothing here changes how v1–v4 behave unless you switch a feature on. The Raspberry Pi is **not** needed: any machine
(Peer P, Dashboard D, a USB-mounted disk, another laptop) can be the vault remote.

## What v5 fixes

| Gap | Fix | Switch on | Check |
|---|---|---|---|
| Vault readable if the disk is stolen / vault is the target | AES-256-GCM encryption at rest (git clean/smudge filter), key in `data/vault.key` | `"encrypt": true` in `protect.json` (keep the key OFF T) | `ransomware/test_guard.py` |
| Attacker with root on T deletes or rewrites the vault | Append-only push of every commit to an off-machine remote | `bash multi/make_vault_remote.sh` on any peer, then `"remote": "<ssh url>"` | `test_guard.py` (append-only + fallback branch) |
| Attacker IPs public on the chain (privacy) | Reports store `enc1:` tokens (AES-GCM, deterministic); only nodes with `CHAIN_IP_KEY` can read them | `CHAIN_IP_KEY` in `config.env` | `detector/test_v5.py` |
| Blocking the gateway / DNS / a whole office NAT | CIDR never-block list | `WHITELIST_CIDRS=10.0.0.0/8,...` | `detector/test_v5.py` |
| Defenders themselves are attacked, stopped or edited | `multi/selfguard.py`: signed file manifest, process watch + restart, heartbeat freshness, freeze on tamper; `install_services.sh` makes everything systemd services that restart on failure | `python3 multi/selfguard.py --init`, `SELFGUARD_KEY` | `detector/test_v5.py` |
| "Does it really work, and how often does it cry wolf?" | `eval/run_eval.py` writes `eval/REPORT.md` — false alarms on normal behaviour, misses and time-to-detect for attacks | `python3 eval/run_eval.py` | the report itself |

### What the evaluation changed
The first run showed that the login rule "success after >=2 failures" flagged ~6% of ordinary users who mistyped a
password. The default is now 4 failures (`--after-fails`); the unit test and the evaluation use that value.

## What is still NOT covered (be upfront about these in a viva)

* **Chain is one Hardhat node** — a single point of failure and not a real distributed ledger. Fix needs multiple
  validator machines (Clique/IBFT/Besu); it is a deployment change, not a code patch.
* **Spoofed-source and link-saturating DDoS**, sub-threshold slow scans, ARP spoof that clones the gateway MAC without
  changing the gateway entry (see `eval/REPORT.md` MISSED rows). Upstream/ISP filtering is the only real answer to saturation.
* **Stolen credentials used once from a normal place and hour** — looks identical to the real user.
* **Plausible fake sensor values that match neighbours**, GPS spoofing, RF jamming, physical access, SCADA/Modbus protocol attacks.
* **Windows-native ransomware, boot/disk-level encryption**, insider with the vault key, phishing.
* **Identity**: node membership is by chain address; there is no PKI / certificate authority.
* **Standards**: no STIX/TAXII or SIEM export yet.
* **Selfguard** can be stopped by an attacker who already has root (it raises the bar and makes quiet tampering visible).
* The evaluation uses simulated workloads and synthetic attackers — it measures detection logic, not real malware.

## Quick run
```bash
python3 detector/test_v5.py && python3 detector/test_flood.py && python3 detector/test_more_attacks.py
python3 ransomware/test_guard.py
python3 eval/run_eval.py
```
