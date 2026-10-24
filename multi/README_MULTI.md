# Dual-Shield on four laptops

| Laptop | Role | Runs | Needs Docker? |
|---|---|---|---|
| **D** | Dashboard + blockchain | Hardhat chain, contract, dashboard | no |
| **T** | Target | SSH server, log parser, ipset, ransomware watcher, snapshot | no |
| **P** | Peer | chain listener, ipset | no |
| **A** | Attacker | Hydra | no |

The one-laptop Docker lab (`./start_lab.sh`, `./demo.sh`) is unchanged and remains the main demo and the fallback.
Everything below is in `multi/`. T and P run directly on the laptop (as root), not in containers, so T sees the attacker's real address.

## 1. Network (once)
- All four laptops on one router or phone hotspot (not venue Wi-Fi). Write each address from `hostname -I`.
- **Windows laptops running WSL2 (D, T, P, A):** other laptops can only reach WSL if it shares the Windows address.
  1. Windows 11 22H2 or newer and `wsl --update`.
  2. Create `C:\Users\<you>\.wslconfig` with
     ```
     [wsl2]
     networkingMode=mirrored
     ```
  3. In PowerShell as Administrator: `wsl --shutdown`, then
     `Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow`
  4. Allow the ports in Windows Firewall (PowerShell as Administrator):
     `New-NetFirewallRule -DisplayName DualShield -Direction Inbound -Protocol TCP -LocalPort 22,3000,8545,8800 -Action Allow`
  5. Open WSL again: `hostname -I` should now show the Windows LAN address.
  Do NOT use `netsh interface portproxy` for T: it hides the attacker's address, so the wrong address would be blocked.
- Clocks: the timeline compares timestamps from different laptops. Run `w32tm /resync` in Administrator PowerShell, then `sudo hwclock -s` in WSL, on every laptop.

## 2. Install (once per laptop)
```
git clone https://github.com/Deepanshu-105/DUAL-SHIELD.git && cd DUAL-SHIELD
git checkout multi-laptop          # until it is merged into main
cp multi/config.env.example multi/config.env     # same four IPs on all four laptops
nano multi/config.env
```
Then, on each laptop only its own script:
`multi/install_D.sh` (D), `sudo multi/install_T.sh` (T), `sudo multi/install_P.sh` (P), `multi/install_A.sh` (A).
Check the network from any laptop: `multi/check_net.sh`.

## 3. Start order (each in its own terminal; T and P stay in the foreground)
1. **D:** `multi/start_D.sh` (starts the chain, deploys, then the dashboard on http://localhost:3000).
2. **T:** `sudo multi/start_T.sh` (wait for `T READY`).
3. **P:** `sudo multi/start_P.sh` (wait for `P READY`).
4. Dashboard on D should show Chain live and both layer pills green. Restarting D wipes the chain, so restart T and P afterwards.

## 4. The demo
1. **A:** `multi/attack_A.sh`. T's terminal shows `[FAIL]` x3, `[BLOCKED]`; P's terminal shows `EVENT` and `PEER_BLOCK`; A prints `BLOCKED: port 22 ... no longer answers`.
2. **D:** dashboard shows threat confirmed, blocked lists on T and P, timeline.
3. **D (or T):** `multi/ransomware_trigger.sh`. Dashboard shows flagged 3, kills 1. (A cannot trigger this: it is blocked by now. The step stands for malware already inside T.)
4. **D:** click **Roll back to clean state**. Expect `ANCHOR_MATCH` and `ROLLBACK_OK 10 of 10`.
5. Re-run: `sudo multi/start_T.sh` and `sudo multi/start_P.sh` again (clears the blocks), then repeat.

## 5. Honest limits
- The second report that makes consensus (K=2) is still scripted (`COREPORT=1`): only T detects attacks.
- The chain is one local Hardhat node on D with instant mining.
- The ransomware is the mock, started through T's agent; it only touches `ransomware/data/sample_copy`.
- The agent on T and P is for the lab only (token header, no encryption).

## 6. Troubleshooting
| Symptom | Fix |
|---|---|
| `check_net.sh` ping fails | Same router? Windows Firewall? Mirrored networking set and `wsl --shutdown` done? |
| `cannot fetch the contract` | Start D first; `curl http://<D_IP>:3000/localhost.json` from T should print JSON |
| A is never blocked but T shows `[FAIL] ... from 172.x` | T sees the wrong source address (NAT): use mirrored networking or a native Ubuntu laptop |
| Dashboard `blocked` tiles empty | agent not running on T or P; `curl -H 'X-Token: dualshield' http://<T_IP>:8800/health` |
| `ANCHOR_MISSING` | `sudo multi/start_T.sh` again (it anchors the clean state for `A_IP`) |
