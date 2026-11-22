---
title: "DualShield — Final Guide (demo, threat model, viva, 10/10 checklist)"
---

# 1. What a 10/10 student project needs (and where DualShield stands)

| Needed | Status | What you still do |
|---|---|---|
| A real problem and a clear idea | Done | Say it in one line: *"Machines share attack evidence through a blockchain, so one attacked machine protects all others; and ransomware is killed and the files are restored from a protected vault."* |
| Working system | Done on one laptop (20 scenarios, 0 problems) | Run it once on separate VMs (section 2) |
| Tests | Done (chaincode 25, peer trust 23, block policy 10, agent 9, keeper 7, and more) | Run `./run_all_tests.sh` and keep the output |
| **Proof on real machines** | **Missing** | Multi-VM run + `multi/collect_evidence.sh` (section 2) |
| **Real ransomware result** | **Missing** | Only in an isolated VM, with the supervisor's written approval (section 3) |
| Security thinking and honest limits | Done | Use the threat model (section 4) |
| Viva readiness | This guide | Read section 5 twice |

Do the two **Missing** rows and the project is as strong as a student project can be. Nobody expects a product.

# 2. Multi-VM proof run (about 60 minutes)

Machines: **D** (WSL on the laptop: dashboard + Fabric chain), **T** (target VM), **P** (peer VM), **A** (Kali attacker VM). All on one host-only/bridged network where they can reach each other. T and P must be real Linux VMs, not WSL.

1. Copy the v13.13 to v13.17 zips to Windows Downloads. On D (WSL):
   `cd ~/DUAL-SHIELD`, unzip the zips in order (13_13, 13_14, 13_15, 13_16, 13_17), then `python3 apply_v13_16.py`.
2. In `multi/config.env` set `PRODUCTION=1` (this turns on TLS, strict gateway, detectors, kept blocks).
3. D: `multi/start_D.sh`. T: `sudo multi/start_T.sh`. P: `sudo multi/start_P.sh`.
4. D: `python3 multi/check_D.py` (the two FAILs from before should now be PASS). T: `sudo python3 multi/check_T.py`.
5. A: run the attack from `multi/attack_A.sh` or `multi/demo_menu_A.sh`.
6. Watch the dashboard: T detects, reports to the chain, P confirms, consensus (K = 2) is reached, the address is blocked on T **and** P.
7. D: `multi/collect_evidence.sh`. Take screenshots of: dashboard before/after, `check_D`, `check_T`, the blocked list, the consensus event.

# 3. Ransomware test (isolated VM only)

- Use only the mock ransomware shipped with the project (`ransomware/mock_crypto.py`, started from the dashboard or `multi/ransomware_trigger.sh`). It encrypts only the sample folder.
- **Never** run real malware on your laptop, on the college network or on a VM that is connected to a shared folder. A real sample needs an isolated VM, a snapshot, no network, and your supervisor's **written** approval. DualShield does not ship real ransomware and nobody on the team should write one.
- Show: ransomware starts, the guard detects it, the process is killed, the vault restores the files, the recovery report shows the files verified (hash check).

# 4. Threat model (one page)

**What we protect:** the target machine's services and files; the shared chain (who is blocked, who is trusted); the dashboard (the operator's control).

**Attackers considered**

| Attacker | What he tries | What stops or shows it |
|---|---|---|
| Outside attacker (A) | SSH brute force, scans, floods, ARP tricks | T's detectors report; K-of-N peers confirm; blocks everywhere |
| One bad peer | Frames an innocent address or our own infrastructure | Needs K confirmations; infrastructure is never blocked; peer_trust scores it and proposes revoke |
| Two bad peers of different organisations | Confirm a false block together | `minOrgs`, TTL (evidence-less block expires in 1 h), circuit breaker, governors can overrule |
| Quiet bad peer | Never reports, or does not apply blocks | Enforcement audit (NOT_ENFORCING), liveness (SILENT), quorum alert |
| Network attacker | Forges or replays agent messages | HMAC-signed requests and answers, nonce replay protection, mutual TLS, IP allow-list, lockout |
| Ransomware on T | Encrypts files, deletes backups | Behaviour detection, kill, vault owned by root, verified restore |
| Someone stealing the dashboard login | Password guessing | TOTP + backup codes, sealed secrets, audit mirror |
| Process crash / tamper on T | Wipes blocks by restart or `ipset flush` | Block journal + blockkeeper restores and logs BLOCKKEEPER_TAMPER |

**Out of scope (say it openly):** an attacker with root on T or P (we make it loud, not impossible); a compromised majority of peers; kernel-level malware; the hardware. Windows has no kernel hook (ETW failed), so the Windows kill path is a 3-4 s process scan.

# 5. Viva questions and short answers

1. **What is DualShield in one line?** A two-layer defence: a blockchain-based shared network defence, plus ransomware detection, kill and vault recovery.
2. **Why a blockchain?** Many machines must agree on who is an attacker without trusting one server; the ledger is shared, signed and tamper-evident. Hyperledger Fabric has no gas cost and fits an organisation setting.
3. **Why Fabric and not Ethereum?** Permissioned network (known identities), no gas, fast finality, chaincode in JavaScript, organisations (MSPs) built in.
4. **How does Layer 1 decide to block?** The target detects and reports. Peers review. When K = 2 distinct reporters (or the quorum percentage of nodes) confirm within the 60 s window, the chaincode emits a consensus event and every node blocks the address.
5. **What if one peer lies?** One report is never enough. A lying peer is scored by peer_trust and can be revoked by governance.
6. **What if two peers lie together?** `minOrgs` can require different organisations, evidence-less blocks expire after an hour, a circuit breaker stops mass framing, and governors can overrule. A real limit remains: a compromised majority cannot be stopped.
7. **What is stake and slashing?** A node puts stake at risk when it reports; if a report is overruled the stake is cut (slashed). It makes false reports expensive.
8. **How do you stop us blocking our own servers?** `block_policy`: DNS servers, gateway, D, T, P, loopback and link-local addresses are never blocked.
9. **How does Layer 2 detect ransomware?** By behaviour on the protected folder (many writes, high-entropy content via chi-square, header and size change) and a file fingerprint that treats a *move* as not a delete, to avoid false positives.
10. **How does recovery work?** A gated commit copies verified files into a vault owned by root; after an attack the process is killed and files are restored from the vault with a hash check.
11. **Why can ransomware not delete the vault?** It is root-owned and its parent directory is sticky; a normal-user process cannot remove it.
12. **What did not work?** Windows ETW: our own listener flooded the event stream and the writer could not be identified. We turned it off and say so. The real fix is a minifilter driver.
13. **How is the dashboard secured?** TOTP 2-step, one-time backup codes, secrets sealed with AES-256-GCM (scrypt key), recovery key, TLS, audit log with a second copy.
14. **What happens if T is restarted by an attacker?** Blocks are journaled before they are applied and restored by blockkeeper; logs are appended, not emptied.
15. **How do you know peers really apply blocks?** D asks their signed agent for the blocked list and compares it with confirmed blocks (enforcement audit).
16. **What are the limits?** Root on a node, compromised majority, a quiet detector that never lies loudly, Windows kill delay, and no real-ransomware or large-scale test yet. (Say this before they ask.)
17. **What would you build next?** A kernel/minifilter agent, an external security review, scale tests with many nodes, packaged installers.
18. **Why is it not 10/10 as a product?** It is a prototype: proof on real machines, an outside audit and a kernel agent are missing. As a student project it is complete and tested.

# 6. Demo script (15 minutes)

1. (1 min) Problem and idea in two sentences.
2. (2 min) Architecture picture: A, T, P, D, chain.
3. (4 min) Layer 1 live: attack from A, show T detect, P confirm, block on both, dashboard.
4. (3 min) Peer protection: show the trust badge, explain "a peer cannot frame our infrastructure".
5. (3 min) Layer 2 live: mock ransomware, kill, restore, recovery report.
6. (1 min) Hardening: `check_D`, `check_T` screenshots.
7. (1 min) Limits slide (section 4 "Out of scope") and next steps.

Keep a recording of a successful run as a backup in case the live demo fails.
