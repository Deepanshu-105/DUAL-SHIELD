# v13.13 - protection against a peer that turns bad (compromised laptop / insider)
Layers (what already existed + what is new):
 1 already: K=2 (one node alone can never block), stake + slashing of a lone report, rate limit per node, governors can overrule and revoke, listeners never block D/T/P (WHITELIST_EXTRA).
 2 NEW chaincode: minOrgs (governance kind 11, dashboard Governance "Set minimum organisations"): a threat is confirmed only when at least minOrgs DIFFERENT organisations reported it.
   Default 1 (old behaviour). Set 2 once both organisations have nodes: two compromised nodes of ONE organisation can then never block anything.
 3 NEW chaincode fix: a slashed node now leaves the quorum count (nodeCount was left too high; with quorumPct it made confirmation harder than intended).
 4 NEW network/peer_trust.py (started by start_D.sh): scores every node from chain events: reports an address of our own infrastructure +100 (= SUSPEND at once), governor overrule +50,
   slash +20, flooding +30; halves every 24 h; 40 = WATCH, 100 = SUSPEND. SUSPEND -> audit line (multi/logs/peer_trust_audit.log), webhook, and with PRODUCTION=1 the owner proposes "Revoke a node"
   (executes at once when the governor threshold is 1, otherwise the governors approve it in the dashboard). Never acts against the owner/governors (TRUST_EXEMPT adds more). Collusion ALERT (no points).
   Old history is not replayed (events have no time stamp). The dashboard Governance tab shows a trusted / watched / SUSPENDED badge per node. check_D.py shows whether the monitor runs.
Tests: chaincode unit tests (npm test in fabric/chaincode/cityshield: 25 pass), network/test_peer_trust.py (14 logic checks), fabric/test_trust.py on a REAL Fabric network
 (same-org nodes cannot confirm with minOrgs=2, other-org node completes it, slash lowers nodeCount, a node that reports our infrastructure is revoked and the others are untouched).
Install: unzip -o at repo root; multi/start_D.sh (it restarts the chaincode with the new code; the ledger stays). Then, when both organisations have nodes: dashboard > Governance > kind 11, value 2.
Limits: a node that stays quiet or reports only plausible attackers is not caught by scoring; two compromised nodes of DIFFERENT organisations can still confirm a block (then governors overrule + revoke).
The dashboard badge was compiled but not clicked through in a browser.
