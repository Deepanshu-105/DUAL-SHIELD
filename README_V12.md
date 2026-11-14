# Dual-Shield v12 — what changed, and what code still cannot fix

| Limitation | v12 change | How to use / test |
|---|---|---|
| Single orderer = single point of failure | `ORDERERS=3` runs 3 Raft orderers (ports 7050/7060/7070, admin 7053/7063/7073). Invoke/deploy fail over to a live orderer. Tested: commits with 3/3 and 2/3 orderers, halts at 1/3, recovers when restarted. | `network.sh reset; ORDERERS=3 network.sh up`; failover test: `network.sh stop-orderer 2` / `start-orderer 2`. Default stays 1. Choose before the first `up` (reset to change). Set `ORDERERS=3` in the environment also when running gateway/status. |
| Writer-pid guessed from /proc samples | Linux: `shield_os.KernelWriters` uses **fanotify** — the kernel reports the pid of each write. killrule tries it first (`how=kernel-fanotify`), then open-file, then top-writer. Needs root; silently falls back otherwise. `KERNEL_HOOK=0` disables. | `sudo` the guard; tested with real fanotify events. |
| Guard/listener can be killed or edited | `multi/harden_linux.sh apply` — chattr +i on code/config, systemd units with `Restart=always`. `undo` reverses. | `sudo multi/harden_linux.sh apply --dry-run` first. |
| Host-level flood | same script: SYN cookies, backlog, rp_filter, per-source SYN hashlimit + connlimit chain `DUALSHIELD_RL`. | env SYN_RATE, SYN_BURST, CONN_MAX, PROTECT_PORTS |
| Multi-host Fabric | Orderers/peers bind 127.0.0.1 by design; moving them to separate machines means changing the addresses in `configtx.yaml`, `crypto-config.yaml` SANS and the peer/orderer listen env to real IPs. Not automated here (untested = not claimed). | — |

## Still NOT fixable by code (be honest in the viva)
- **Root / Administrator attacker**: chattr and services can be undone by root; only an external, tamper-evident log (the chain + off-box syslog) makes it detectable, not impossible.
- **Windows kernel hook**: needs a signed minifilter driver (Microsoft-signed, C, WDK). Windows path still uses polling + open-handle/psutil ranking.
- **Spoofed / saturating DDoS**: bandwidth floods must be absorbed upstream (ISP, CDN, scrubbing). The local floor only protects the host's own CPU/connection table.
- **Vault at scale**: git-based vault suits project-sized data; terabytes need a dedicated backup system (object-lock, deduplication).
- **Real Windows, real ransomware, pilot users**: must be tested on real machines/VMs — nothing in the sandbox substitutes for that.
