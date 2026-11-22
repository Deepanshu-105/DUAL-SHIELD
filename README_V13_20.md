# DualShield v13.20 — more attacks: detect, block, retrieve
## detector/web_guard.py (T, if it runs a web server)
Detect (nginx/apache combined log): SQL injection, XSS, path traversal, command injection / log4shell, probes (.env, .git, wp-login, phpmyadmin ...), scanner tools (sqlmap, nikto ...), 404 scanning, HTTP flood (200 req / 10 s).
Block: score >= 10 in 60 s -> reported to the chain (K-of-N consensus blocks it on every node) and blocked at once. Own infrastructure is never blocked.
Retrieve: `--snapshot` after a clean deploy; a defaced/changed/deleted file is restored from the root-only snapshot, a NEW script file (php, jsp, aspx, cgi, py, sh ...) is quarantined (mode 000), and the most suspicious recent address is blocked.
## detector/host_guard.py (T and P)
Detect (process scan): reverse shells (/dev/tcp, nc -e, socat, script sockets, "bash -i" only with a real remote connection), crypto miners (xmrig, stratum+tcp ...). Alert only: program running from /tmp, /dev/shm, /var/tmp or from a deleted file.
Block: process killed, its remote address blocked in and out and reported to the chain. Retrieve: the program file is moved to a quarantine with a record (`--list`, `--restore ID`; restored without execute permission). System programs (/usr, /bin ...) are never moved; DualShield's own processes are never touched.
## Install (after v13.16)
unzip; python3 apply_v13_20.py; restart T/P. ON by default with PRODUCTION=1; lab: WEB_GUARD=1 / HOST_GUARD=1 in multi/config.env. Web: WEB_LOG (default nginx or apache access log), WEB_ROOT (default /var/www/html).
Tests: python3 detector/test_web_guard.py (19), python3 detector/test_host_guard.py (10).
## Honest limits
Signature based: a new payload style can pass; behind a reverse proxy the log must show the real client address; a renamed miner with a quiet command line can pass; root can stop the guards (D then sees the node SILENT). Tested with sample log lines and a fake /proc, not on a real T/P yet. Test the web attacks only against YOUR OWN lab T from your own A VM.
