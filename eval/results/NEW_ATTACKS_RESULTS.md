# Evaluation of the v13.20 guards (offline benchmark)

Made by `python3 eval/eval_new_attacks.py` on 2026-11-22. Small hand-written sample sets, no network traffic: read it as what the rules catch and miss.

**Read this first.** The rows without 'held-out' are the *development* samples: the rules were tuned until they passed, so those numbers are optimistic. The rows marked **held-out** were written after tuning and never used to tune: they are the honest estimate. A WEAK rule (a select...from sentence, 4 points) can flag a normal search but it never blocks on its own (block needs 10 points in 60 s).

| Area | Class | Samples | Caught / count | Note |
|---|---|---|---|---|
| web | SQL injection | 15 | 15 (100%) | requests flagged; attacker BLOCKED after 1 request(s) |
| web | XSS | 8 | 8 (100%) | requests flagged; attacker BLOCKED after 2 request(s) |
| web | Path traversal | 8 | 8 (100%) | requests flagged; attacker BLOCKED after 1 request(s) |
| web | Command injection / log4shell | 10 | 10 (100%) | requests flagged; attacker BLOCKED after 1 request(s) |
| web | Probes (sensitive files) | 7 | 7 (100%) | requests flagged; attacker BLOCKED after 3 request(s) |
| web | Probes (admin tools) | 7 | 7 (100%) | requests flagged; attacker BLOCKED after 3 request(s) |
| web | Scanner tools (user agent) | 8 | 8 (100%) | blocked on the first request |
| web | HTTP flood (50 req/s) | 1 | 1 | blocked after 200 requests (4.0 s) |
| web | 404 scanning (1 req/s) | 1 | 1 | blocked after 20 requests |
| web | BENIGN requests | 39 | 0 | requests wrongly flagged (lower is better) |
| web | BENIGN visitors (40 visitors x 39 pages) | 40 | 0 | visitors wrongly BLOCKED (lower is better) |
| web | BENIGN admin logging in to an existing /wp-login.php 6x | 1 | 0 | admin wrongly BLOCKED (lower is better) |
| web | Speed | 20000 | 20000 | 57155 log lines per second, 17.5 microseconds per line |
| retrieve | Defaced / emptied / deleted files restored (bit for bit) | 5 | 5 (100%) | 1723700 bytes restored in 1.3 ms |
| retrieve | New script files (12 types) quarantined | 12 | 12 (100%) | web shells moved out, mode 000 |
| retrieve | New harmless files left untouched | 4 | 4 (100%) | not quarantined, only noted |
| host | Reverse shells (15 techniques, with a remote connection) | 15 | 15 (100%) | killed; remote address found from the socket |
| host | Crypto miners (9 variants incl. renamed) | 9 | 9 (100%) | killed |
| host | BENIGN processes (40 incl. ssh sessions, grep/man of 'xmrig', nc -l) | 40 | 0 | wrongly killed (lower is better) |
| host | Speed (one full scan of 1000 processes) | 1000 | 1000 | 64 ms per scan (includes building the fake /proc) |
| held-out web | SQL injection | 10 | 10 (100%) | requests flagged (samples not used for tuning) |
| held-out web | XSS | 6 | 6 (100%) | requests flagged (samples not used for tuning) |
| held-out web | Path traversal | 6 | 6 (100%) | requests flagged (samples not used for tuning) |
| held-out web | Command injection / log4shell | 6 | 6 (100%) | requests flagged (samples not used for tuning) |
| held-out web | BENIGN requests | 15 | 1 | wrongly flagged (lower is better) |
| held-out host | Reverse shells | 8 | 8 (100%) | killed |
| held-out host | Crypto miners | 4 | 3 (75%) | killed |
| held-out host | BENIGN processes | 16 | 0 | wrongly killed (lower is better) |

## Misses and false positives (printed, not hidden)

- HELD-OUT web BENIGN flagged: /search?q=how+to+select+a+laptop+from+the+store
- HELD-OUT host miner not caught: ./javad
