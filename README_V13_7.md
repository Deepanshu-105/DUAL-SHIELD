# v13.7 - weak points of Layer 1
1. Attack seen by only ONE node: that node's report goes on-chain (below quorum). Every node's listener now puts the IP on a local watchlist (10 min,
   WATCH_TTL). A node's SSH detector then blocks/reports that IP on the FIRST failed login (threshold 1 instead of 3), so a second independent report can reach K.
   Off switch: WATCHLIST=0 on the listener. The watchlist never blocks by itself.
2. Evidence: the SSH detector records which IPs THIS node saw itself; on a consensus block the listener logs evidence=local or evidence=consensus-only.
3. Compromised nodes: the quorum percent is a governance setting - with 5+ nodes raise it (dashboard > Governance > "Set quorum percent", e.g. 60), so 2 bad nodes cannot block alone.
   Reports-per-hour limit and the governors' overrule (slashes the reporters) already exist.
Test (needs the running network+gateway): python3 network/test_watchlist.py
Limits: only ssh_parser uses the watchlist (flood_detector not yet); a node that lies can make others watch an IP (they still block only after seeing a failed login themselves).
