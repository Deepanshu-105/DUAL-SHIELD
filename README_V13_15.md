# DualShield v13.15 — target (T) security gaps

## multi/agent.py (the signed API on T/P)
- Source allow-list (AGENT_ALLOW; start_T.sh sets it to D_IP when PRODUCTION=1): other addresses are dropped before TLS/HMAC.
- Lockout: 10 bad signatures in 60 s -> that address is dropped for 300 s (AGENT_FAIL_MAX / AGENT_FAIL_WINDOW / AGENT_BAN_SECS).
- Body cap 64 KB (413), socket timeout 15 s (slow-client attack).
- /ransomware (mock attack, WIPES the vault) returns 403 when PRODUCTION=1.
## multi/start_T.sh
- PRODUCTION=1 (or KEEP_BLOCKS=1): blocks are saved every 20 s to /var/lib/dualshield/blocklist.save and restored on start; logs are appended, not emptied. Before, a restart/crash erased all blocks and evidence.
- PRODUCTION=1: flood, login and ARP detectors are ON by default (were opt-in).
## multi/check_T.py  (sudo python3 multi/check_T.py)
PASS/WARN/FAIL report: config, agent/parser/detectors running, ipset + iptables rule, saved blocks, selfguard, DDoS floor, ssh root/password, agent allow-list, vault ownership.
## Honest limits
- A root attacker on T can still stop everything (selfguard/systemd raise the bar only). Real fix = kernel/driver-level protection.
- Allow-list/ban work on IP addresses: behind NAT or with a spoofed-on-LAN D address they help less; mutual TLS (PRODUCTION=1) is the real identity.
- ipset save runs every 20 s: blocks added in the last 20 s can be lost on a hard crash.
## Install
unzip -o DualShield_v13_15_target_security.zip at repo root; on T: sudo multi/start_T.sh (set PRODUCTION=1 in multi/config.env for all of it); check: sudo python3 multi/check_T.py
Tests: python3 multi/test_agent_hardening.py (9).
