#!/usr/bin/env python3
"""Web attack guard for T: DETECT (access log), BLOCK (through the chain), RETRIEVE (restore defaced files, quarantine web shells).

  python3 detector/web_guard.py --snapshot          # after a clean deploy: copy WEB_ROOT to the root-only snapshot + hash manifest
  python3 detector/web_guard.py                     # follow WEB_LOG and watch WEB_ROOT (loop)
  python3 detector/web_guard.py --restore-check     # one integrity check now

Detects in nginx/apache "combined" logs: SQL injection, XSS, path traversal, command injection / log4shell, probes for .env/.git/wp-login/
phpmyadmin..., scanner tools (sqlmap, nikto ...), 404 scanning and HTTP floods. An address whose score reaches WEB_BLOCK_SCORE (10) inside
WEB_WINDOW (60 s) is reported to the chain (K-of-N consensus then blocks it on every node) and blocked here at once. Own infrastructure is never blocked.
RETRIEVE: a changed or deleted file of the web root is restored from the snapshot; a NEW script file (php, jsp, aspx, cgi, py, sh ...) is moved
to the quarantine (mode 000, reversible) and the most suspicious recent address is blocked.
Env: WEB_LOG, WEB_ROOT, WEB_SNAP, WEB_QUAR, WEB_BLOCK_SCORE, WEB_WINDOW, WEB_FLOOD (200 requests / 10 s), WEB_EVERY (5 s), WHITELIST_EXTRA.
Honest limit: signature based (a new payload style can pass); behind a reverse proxy the log must show the real client address; root can stop this guard.
"""
import hashlib, os, re, shutil, subprocess, sys, time
from collections import defaultdict, deque
from urllib.parse import unquote_plus
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "network")); sys.path.insert(0, os.path.join(ROOT, "multi"))
WEB_LOG = os.environ.get("WEB_LOG", "")
WEB_ROOT = os.environ.get("WEB_ROOT", "/var/www/html")
SNAP = os.environ.get("WEB_SNAP", "/var/lib/dualshield/web_snapshot")
QUAR = os.environ.get("WEB_QUAR", "/var/lib/dualshield/web_quarantine")
BLOCK_SCORE = float(os.environ.get("WEB_BLOCK_SCORE", "10")); WINDOW = float(os.environ.get("WEB_WINDOW", "60"))
FLOOD_N, FLOOD_S = int(os.environ.get("WEB_FLOOD", "200")), 10.0
EVERY = float(os.environ.get("WEB_EVERY", "5"))
SCRIPT_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh", ".exe", ".war")
LINE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
SIGS = [  # (name, points, regex on the url-decoded request)
 ("sqli", 10, re.compile(r"(?i)(union(\s|\+|/\*.*?\*/)+(all(\s|/\*.*?\*/)+)?select|\b(or|and)\b\s*\(?\s*'?\d+'?\s*\)?\s*=\s*\(?\s*'?\d+|'\s*(or|and)\s*'|'\s*(--|#|/\*)|sleep\s*\(\s*\d|benchmark\s*\(|information_schema|;\s*drop\s+table|load_file\s*\(|\bwaitfor\s+delay\b|\bextractvalue\s*\(|;\s*(exec|execute|insert\s+into|update\s+\w+\s+set|delete\s+from|truncate|alter\s+table|create\s+(table|user))\b|xp_cmdshell|\bupdatexml\s*\(|\bprocedure\s+analyse|\binto\s+(out|dump)file\b|\bhaving\s+\d+\s*[=<>]|\border\s+by\s+\d+\s*(--|#|/\*)|\bcast\s*\([^)]{0,80}\bas\s+(int|char|varchar)|\bpg_sleep\s*\(|@@version|\bdatabase\s*\(\s*\)|\b(or|and)\s+'[^']{0,20}'\s*=\s*'?|\)\s*(or|and)\s*\(|\bcase\s+when\b.{0,60}\bthen\b|\b(ord|mid|substring|substr)\s*\(\s*\(?\s*(select|version|user|database)|\bexec(ute)?\s+sp_|\brlike\s*\()")),
 ("sqli", 4, re.compile(r"(?i)\bselect\s+[^&]{1,60}?\s+from\s+[\w.`\[\]]+|\b(or|and)\s+\d+\s*[<>]=?\s*\d+")),      # weak: a natural-language search can contain it, so it only scores 4
 ("xss", 8, re.compile(r"(?i)(<\s*script|javascript:|\bon(error|load|mouseover|focus|click)\s*=|<\s*iframe|<\s*svg|<\s*[a-z][^>]{0,80}\bon[a-z]{3,}\s*=|\bdata:text/html)")),
 ("xss", 4, re.compile(r"(?is)^(?!.*<)(?!.*javascript:).*\b(alert|prompt|confirm)\s*[(`]")),     # weak: script-context breakout like  '-alert(1)-'  (a page about JavaScript can contain it, so 4 points only)
 ("traversal", 10, re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini|=\s*/(etc|proc|root)/|=\s*/var/(log|www)/|\.ssh/|\.bash_history|\bid_rsa\b|\b(php|expect|phar|gopher|zip)://|\bfile:///|\bdata://|windows/system32/config)")),
 ("rce", 10, re.compile(r"(?i)(\$\{\s*jndi:|\$\{[^}]{0,30}(lower|upper|env|sys|date|java)\s*:|\$\{[^}]{0,40}::-|%\{\s*\(?\s*#|\bcmd(\.exe)?\s+/c\b|&\s*(ping|cmd)(\.exe)?\s+[-/]|;\s*/(usr/)?s?bin/\w+|;\s*(cat|ls|id|wget|curl|nc|bash|sh|whoami|python\d?|php|perl|ruby|node|rm|chmod|uname|echo|ping|sleep|mkfifo|powershell)\b|(\|\||&&|\|)\s*(id|whoami|uname|ls|cat|ping|sleep|echo|nc|curl|wget)\b(?!\s*=)|[\r\n]\s*(id|whoami|uname|cat|ls|wget|curl|nc|bash|/bin/\w+)\b|\|\s*(sh|bash)\b|`[^`]+`|\$\([^)]+\)|/bin/(ba)?sh|cmd\.exe|powershell|base64\s+-d)")),
 ("probe", 3, re.compile(r"(?i)(/\.env\b|/\.git/|/\.svn/|/(c99|r57|shell|webshell|cmd)\.(php|jsp|asp)|/config\.php\.bak|/backup\.(sql|zip|tar)|/etc/passwd)")),     # exposed secrets: serious even when the answer is 200
]
APP_PROBE = re.compile(r"(?i)(wp-login\.php|xmlrpc\.php|/phpmyadmin|/vendor/phpunit|/actuator|/boaform|/cgi-bin/)")   # real admin tools: 3 points if the answer is an error, only 1 if the page exists (an admin using it)
RAW_SIGS = [("traversal", 10, re.compile(r"(?i)(%c0%af|%c1%9c|%c0%ae|%252e%252e|\.\.%2f|\.\.%5c)"))]    # encodings that are an attack by themselves, checked on the undecoded request
SCANNER = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|hydra|zgrab|nuclei|havij|w3af|burpcollaborator)")


def decoded(url):
    return unquote_plus(unquote_plus(url))


def classify(line):
    """-> (ip, method, status, [(name, points)]) or None for a line that is not a request."""
    m = LINE.match(line)
    if not m: return None
    ip, method, url, status, ua = m.group(1), m.group(2), decoded(m.group(3)).replace("\x00", ""), int(m.group(4)), m.group(5) or ""
    hits = [(n, p) for n, p, rx in SIGS if rx.search(url)]
    hits += [(n, p) for n, p, rx in RAW_SIGS if rx.search(m.group(3))]
    if APP_PROBE.search(url): hits.append(("probe", 3 if status >= 400 else 1))
    if SCANNER.search(ua): hits.append(("scanner", 10))
    if status == 404: hits.append(("404", 0.5))
    if status in (401, 403): hits.append(("denied", 0.5))
    return ip, method, status, hits


class WebGuard:
    def __init__(self, report, block, never_block, now=time.time, log=print):
        self.report, self.block, self.never, self.now, self.log = report, block, never_block, now, log
        self.score = defaultdict(deque); self.reqs = defaultdict(deque); self.blocked = set(); self.posts = {}
    def _total(self, ip, t):
        d = self.score[ip]
        while d and t - d[0][0] > WINDOW: d.popleft()
        return sum(p for _, p, _ in d)
    def feed(self, line):
        c = classify(line)
        if not c: return None
        ip, method, status, hits = c; t = self.now()
        q = self.reqs[ip]; q.append(t)
        while q and t - q[0] > FLOOD_S: q.popleft()
        pts = sum(p for _, p in hits)
        for n, p in hits:
            self.score[ip].append((t, p, n))
        if method in ("POST", "PUT") and pts: self.posts[ip] = t
        why = None
        if len(q) >= FLOOD_N: why = "http-flood %d requests in %d s" % (len(q), FLOOD_S)
        elif self._total(ip, t) >= BLOCK_SCORE:
            names = sorted({n for _, _, n in self.score[ip] if n not in ("404", "denied")}) or ["scanning (404 burst)"]
            why = "web attack: " + ",".join(names)
        if why and ip not in self.blocked:
            r = self.never(ip)
            if r: self.log("WEB_SKIP %s not blocked (%s)" % (ip, r)); self.blocked.add(ip); return None
            self.blocked.add(ip); self.log("WEB_ATTACK %s %s" % (ip, why)); self.report(ip); self.block(ip)
            return ip, why
        return None
    def suspects(self, within=120):
        t = self.now(); out = []
        for ip, d in self.score.items():
            s = sum(p for tt, p, _ in d if t - tt <= within)
            if s >= 3: out.append((s, ip))
        return sorted(out, reverse=True)


def sha(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 16), b""): h.update(b)
    except OSError: return None
    return h.hexdigest()


def walk(root):
    for dp, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dp, fn)
            if os.path.isfile(p) and not os.path.islink(p): yield os.path.relpath(p, root)


def snapshot(web_root=None, snap=None):
    web_root, snap = web_root or WEB_ROOT, snap or SNAP
    if os.path.isdir(snap): shutil.rmtree(snap)
    os.makedirs(os.path.dirname(snap) or ".", exist_ok=True); shutil.copytree(web_root, snap, symlinks=False)
    os.chmod(snap, 0o700); return sum(1 for _ in walk(snap))


class Integrity:
    def __init__(self, web_root, snap, quar, on_suspect, log=print, now=time.time):
        self.root, self.snap, self.quar, self.on_suspect, self.log, self.now = web_root, snap, quar, on_suspect, log, now
        self.known = {}
        for rel in walk(snap): self.known[rel] = sha(os.path.join(snap, rel))
    def check(self):
        """-> {"restored": [...], "quarantined": [...], "new": [...]}"""
        out = {"restored": [], "quarantined": [], "new": []}
        for rel, h in self.known.items():
            cur = os.path.join(self.root, rel)
            if not os.path.exists(cur) or sha(cur) != h:
                os.makedirs(os.path.dirname(cur) or ".", exist_ok=True); shutil.copy2(os.path.join(self.snap, rel), cur)
                out["restored"].append(rel); self.log("WEB_RESTORED %s (changed or deleted: restored from the clean snapshot)" % rel)
        for rel in walk(self.root):
            if rel in self.known: continue
            if rel.lower().endswith(SCRIPT_EXT):
                os.makedirs(self.quar, exist_ok=True); dst = os.path.join(self.quar, "%d_%s.quar" % (int(self.now()), rel.replace(os.sep, "__")))
                shutil.move(os.path.join(self.root, rel), dst); os.chmod(dst, 0)
                out["quarantined"].append(rel); self.log("WEB_QUARANTINED %s (new script file in the web root; moved to %s, mode 000)" % (rel, dst))
            else:
                out["new"].append(rel)
        if out["restored"] or out["quarantined"]: self.on_suspect(out)
        return out


def real():
    import block_policy
    infra = block_policy.local_infra()
    def report(ip):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "network"))
        subprocess.run([sys.executable, os.path.join(ROOT, "network", "chain_report.py"), ip], env=env, capture_output=True, timeout=60)
    def block(ip):
        import shield_os; shield_os.block_init(); shield_os.block_add(ip)
    def never(ip):
        try: return block_policy.never_block_reason(ip, infra)
        except ValueError: return "not an IP address"
    return report, block, never


def follow(path, stop=lambda: False):
    pos = None
    while not stop():
        try:
            with open(path, "r", errors="replace") as f:
                st = os.fstat(f.fileno())
                if pos is None or st.st_size < pos: pos = st.st_size if pos is None else 0
                f.seek(pos); lines = f.readlines(); pos = f.tell()
        except OSError: lines = []
        yield lines; time.sleep(EVERY)


if __name__ == "__main__":
    if "--snapshot" in sys.argv:
        print("snapshot of %s: %d files -> %s" % (WEB_ROOT, snapshot(), SNAP)); sys.exit(0)
    report, block, never = real()
    guard = WebGuard(report, block, never, log=lambda m: print(time.strftime("%H:%M:%S ") + m, flush=True))
    def suspect(out):
        s = guard.suspects()
        if s and s[0][1] not in guard.blocked and not never(s[0][1]):
            ip = s[0][1]; guard.blocked.add(ip); print(time.strftime("%H:%M:%S ") + "WEB_ATTACK %s linked to the file change (score %.0f)" % (ip, s[0][0]), flush=True); report(ip); block(ip)
    integ = Integrity(WEB_ROOT, SNAP, QUAR, suspect, log=lambda m: print(time.strftime("%H:%M:%S ") + m, flush=True)) if os.path.isdir(SNAP) else None
    if "--restore-check" in sys.argv:
        print(integ.check() if integ else "no snapshot yet: run --snapshot after a clean deploy"); sys.exit(0)
    print("WEB_GUARD on  log=%s root=%s snapshot=%s" % (WEB_LOG or "(none)", WEB_ROOT, "yes" if integ else "NO (run --snapshot)"), flush=True)
    last = 0
    for lines in follow(WEB_LOG) if WEB_LOG else iter(lambda: (time.sleep(EVERY) or []), None):
        for ln in lines: guard.feed(ln)
        if integ and time.time() - last >= EVERY: last = time.time(); integ.check()
