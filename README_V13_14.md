# DualShield v13.14 — peer security: the two limits + more

## Limit 2 (two bad nodes of different orgs confirm a block) — network/block_policy.py (listener)
- NEVER block: own infra (D/T/P IPs, WHITELIST_EXTRA), DNS servers, default gateway, own addresses, loopback/link-local/multicast.
- Consensus block WITHOUT local evidence expires after CONSENSUS_TTL (3600 s) -> a framing heals itself. Blocks with local evidence stay.
- Circuit breaker: more than CB_MAX (20) evidence-less consensus blocks in CB_WINDOW (600 s) -> further ones are HELD (not applied) + logged.
- Governors can overrule / revoke; minOrgs=2 (governance kind 11) forces reports from different orgs.
## Limit 1 (a quiet / plausible-only attacker node) — network/peer_trust.py
- Enforcement audit: every 15 s D asks the signed agent of T and P for /ipset; a node that did not apply a confirmed block within 30 s = NOT_ENFORCING (+40).
- Liveness: agent unreachable > 180 s = SILENT (+30). Forged/tampered answer = BAD_ANSWER (+60). Alert when fewer nodes answer than the quorum needs.
- Needs AGENT_SECRET_T / AGENT_SECRET_P in D's environment (start_D.sh already exports them); TRUST_AUDIT_ROLES=T,P.
## Honest limits
- A compromised detector that simply stays quiet or reports only plausible IPs cannot be PROVEN bad without ground truth; we detect odd behaviour, not intent.
- TTL means evidence-less blocks expire (re-reported attacks re-block). Breaker may hold a real mass attack unless a peer has local evidence.
- Audit can false-positive while the breaker holds or the listener refuses an infra IP.
## Install
unzip -o DualShield_v13_14_peer_security.zip (repo root); restart listener on T/P; restart multi/start_D.sh.
Tests: python3 network/test_block_policy.py (10), python3 network/test_peer_trust.py (23), chaincode npm test (25).
