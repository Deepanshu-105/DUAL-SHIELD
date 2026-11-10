# v11: product hardening (what was fixed in code, and what was not)

| Limitation | Fix in v11 | Test |
|---|---|---|
| Lab identities: one process reported for both nodes | **NODE_ID**: T reports as node 1, P (with `PEER_DETECT=1`) guards its own SSH/logons and reports as node 2. With `GATEWAY_LAB=0` the one-laptop shortcut is refused. | `fabric/test_product.py` (target and peer certificates, consensus, shortcut refused) |
| Quarantine could lock a laptop out, default dry | `CONTAIN=apply` needs a non-empty allow list (`CONTAIN_ALLOW`, filled with D and P by start_T); an empty list is refused and runs as dry; quarantine **auto-releases** after `QUARANTINE_MAX_S` (default 900 s) | `multi/test_v11.py` |
| IPv4 only | IPv6 blocked locally on Linux (ipset family inet6 + ip6tables) and Windows; SSH parser and Windows logon watch read IPv6 sources. Chain sharing stays IPv4 (the record format), IPv6 is skipped with a log line. | `multi/test_v11.py` |
| Gateway: no abuse protection | per-client rate limit (429), connection/header timeouts, max connections, graceful stop, `/metrics` (Prometheus text) | `fabric/test_product.py` |
| Flood/ARP missing on Windows | **ARP watch now runs on Windows** (`arp -a`, `route print`); alerts only (no static-ARP repair on Windows). The raw-packet flood detector is still Linux-only. | `multi/test_v11.py` |
| Guard dies and stays dead (Windows) | `windows/install_autostart.ps1`: Task Scheduler task as SYSTEM, at boot, restarts on failure (Linux: `multi/install_services.sh` + selfguard) | **not tested** (needs Windows) |

## Not fixed by code alone (be honest in the viva)
- **Multi-host Fabric, 3+ orderers, real organisations:** needs several machines and an operations plan; the lab still runs both peers and the orderer on D.
- **Kernel hooks (Windows minifilter/ETW, Linux eBPF):** needs a signed driver or eBPF program; the guard still polls.
- **Tamper-proofing against root/Administrator:** the autostart task and selfguard raise the bar; only a protected OS service or an external watchdog stops a determined admin.
- **Spoofed or link-saturating DDoS:** needs upstream filtering (ISP, CDN).
- **Vault scale (git based):** needs block-level snapshots or an object store.
- **Real Windows run, real ransomware samples, real pilot customers.**
