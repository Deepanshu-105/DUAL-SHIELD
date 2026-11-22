# DualShield v13.16 — the three limits of v13.15
1. Hard crash lost the last 20 s of blocks -> write-ahead journal (shield_os writes blocks.desired.json BEFORE every block; fsync). multi/blockkeeper.py --restore re-applies it at start.
2. A root/other process could remove blocks or the iptables DROP rule silently -> blockkeeper checks every 5 s, restores them and logs BLOCKKEEPER_TAMPER (log "keeper", readable by D through the signed agent). Legit unblocks go through shield_os, so no false alarms.
3. IP allow-list alone is weak -> with PRODUCTION=1 the agent refuses to start without TLS (mutual TLS is the identity). start_P.sh gets the same allow-list/PRODUCTION as T.
Still true: root can stop blockkeeper too; D's liveness audit (peer_trust SILENT) then flags the laptop. A kernel-level protection would be a different product.
Install (after v13.15):  python3 apply_v13_16.py   (checks every anchor first; changes nothing if one does not match; *.bak kept)
Test: python3 multi/test_blockkeeper.py (7 checks)
