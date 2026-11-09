# Dual-Shield on Linux and Windows (v10)

Dual-Shield now protects **Linux and Windows laptops** with the same detection logic. Everything that differs between the two systems is in one
file, `multi/shield_os.py`; Layer 1 blocking, Layer 2 kill and containment, the dashboard agent and the peer listener all go through it.

## Which laptop can be which
| Role | Linux | Windows 10/11 | Why |
|---|---|---|---|
| D (dashboard + Fabric chain) | yes | **use WSL2 or Linux** | Fabric's tools are Linux binaries |
| T (target / protected laptop) | yes | **yes (new)** | |
| P (peer) | yes | **yes (new)** | |
| A (attacker) | yes | any (Hydra, mock attackers) | |

## What each system uses
| Job | Linux | Windows |
|---|---|---|
| block an attacker IP (Layer 1) | ipset `city_blacklist` + one iptables DROP rule | one Windows Firewall rule pair (in + out) per IP, `netsh advfirewall` |
| failed-logon source | `/var/log/auth.log` (SSH) | Security log 4625/4624 (RDP, SMB, network logons) + OpenSSH log, converted by `detector/win_logon_watch.py` to auth.log-style lines |
| SSH brute-force parser, slow-login watch, block expiry, peer listener | same code | same code (through `shield_os`) |
| find the ransomware process (Layer 2) | `/proc` open files | psutil open files, then the processes whose write volume grew most (`WriterTracker`) |
| kill | SIGKILL | TerminateProcess on the whole process tree |
| quarantine (containment) | iptables chain `DS_QUAR` | Windows Firewall: allow rules for D and P, default policy block in + out |
| vault, verified restore, canaries, classify (crypto, wiper, double extortion, exfiltration, note-only) | Python + git | **same code**, needs Git for Windows |
| shadow-copy recovery | n/a | `ransomware/shadow_recovery.py` (VSS) |
| flood/port-scan detector, ARP watch | yes | **not available** (need a raw packet socket / `ip neigh`); the Windows Firewall and the logon watch still protect |

## Windows laptop set-up (T or P)
```powershell
# elevated PowerShell (Run as administrator), in the repo folder
powershell -ExecutionPolicy Bypass -File windows\install_windows.ps1     # Git, Python, packages, OpenSSH server, audit policy
notepad multi\config.env       # same file as Linux: D_IP, T_IP, P_IP, AGENT_SECRET_T/P, GATEWAY_PORT=8600 ...  (DISCOVERY must be 0 on Windows)
windows\start_target.ps1       # on T          (or:  windows\start_peer.ps1  on P)
windows\stop.ps1 -Clean        # stop and remove every DualShield firewall rule
```
With `TLS=1`: on D run `multi/make_tls.sh`, copy `multi/tls/target` (T) or `multi/tls/peer` (P) to `multi\tls\node` on the Windows laptop.
D must allow port 8600 (gateway) and 3000/3443 (dashboard) from the Windows laptops, and the Windows laptops allow 8800 from D (the script adds that rule).

## Tests
```bash
python3 multi/test_windows_mode.py     # runs on Linux: Linux commands against fake ipset; Windows commands against a fake netsh/powershell
```
It checks the netsh command lines and rule bookkeeping, quarantine and release, kill by open file and by biggest writer (real processes), the event-log
to auth.log conversion (no replay, loopback/IPv6/interactive ignored), the SSH parser blocking through Windows Firewall rules, and block expiry.

## Honest limits (read before a viva)
- **Tested here:** the logic and the command lines, on Linux with simulated `netsh` and `powershell`. **Not tested on real Windows**: real `netsh`
  output, Event Log field names on your Windows build, PowerShell script execution policy, Windows Defender reactions. Expect small fixes on the first real run.
- **No kernel hook on Windows.** The process behind a file change is found by polling, so a very fast encryptor can finish more files before the kill
  (the vault restores them). Commercial products use minifilter drivers or ETW; that is future work.
- The top-writer fallback ranks processes, it does not prove which process wrote which file. It only runs after 3 files were flagged and never touches
  system processes (svchost, lsass, explorer, ...), Dual-Shield itself or its parent chain.
- A Windows Firewall rule per IP takes about 0.1-0.3 s to create (an ipset entry takes microseconds), so Windows blocks are slower than Linux.
- Windows blocking is IPv4 only. Windows-native ransomware that never touches the watched folders, boot-level attacks, kernel malware and attackers with
  Administrator rights who stop the guard are not covered. The lab holds all keys.
- Real Windows ransomware has not been run. For that, see the lab advice given earlier: isolated VM, no network, snapshots, supervisor approval. The mock
  attackers (`mock_crypto.py`, `mock_wiper.py`) run on Windows because they are plain Python.
