#!/usr/bin/env python3
"""Sends an alert to Telegram / e-mail / a webhook (Slack, Discord, Teams ...) when DualShield sees something serious.   Run on D.

  python3 multi/alert_notify.py            # loop (start_D.sh starts it when an ALERT_* channel is set in multi/config.env)
  python3 multi/alert_notify.py --test     # send one test message to every channel and exit
  python3 multi/alert_notify.py --dry-run  # print what would be sent

Reads the logs of T and P through the signed agent (web_guard, host_guard, node_watch, block keeper, the ransomware guard) and the
peer-trust log of D. Settings (multi/config.env, or the environment):
  ALERT_MIN=high                         lowest severity that is sent: info | medium | high | critical   (default high)
  ALERT_TELEGRAM_TOKEN / ALERT_TELEGRAM_CHAT       bot token and chat id
  ALERT_SMTP_HOST / ALERT_SMTP_PORT(587) / ALERT_SMTP_USER / ALERT_SMTP_PASS / ALERT_MAIL_FROM / ALERT_MAIL_TO
  ALERT_WEBHOOK=https://...              Slack/Teams/Discord incoming webhook
  ALERT_MAX_PER_MIN=10                   more than this in a minute are folded into one "+N more" message (no flood, no spam)
  ALERT_EVERY=10                         seconds between polls
Old log lines are NOT sent at the first start (only what happens afterwards). Messages are plain text, control characters removed, 300 characters at most.
The token and passwords stay in multi/config.env (mode 600; multi/protect_config.sh keeps them out of Git). Rotate them if the file leaks.
Honest limit: an alert is only as good as the guard that wrote the log line; if D or the internet is down nothing is sent (the dashboard still shows it).
"""
import collections, hashlib, json, os, re, smtplib, subprocess, sys, time, urllib.request
from email.message import EmailMessage
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


def cfg():
    d = {}
    try:
        for ln in open(os.path.join(HERE, "config.env")):
            m = re.match(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=(.*)$", ln.rstrip("\n"))
            if m: d[m.group(1)] = m.group(2).split(" #")[0].strip().strip("'\"")
    except OSError: pass
    for k, v in os.environ.items():
        if k.startswith("ALERT_") or k in ("AGENT_SECRET_T", "AGENT_SECRET_P", "T_IP", "P_IP", "TLS"): d[k] = v
    return d


def clean(s, n=300):
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", s)[:n]


def parse(line, node, source):
    """-> {"sev", "title", "text"} or None. Lines of the newer guards start with a time; ransomware lines may start with an epoch number or nothing."""
    m = re.match(r"^(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d|\d\d:\d\d:\d\d|\d+\.\d+) (.*)$", line)
    rest = m.group(1) if m else line
    def ev(sev, title): return {"sev": sev, "title": title, "text": clean("[%s] %s: %s" % (sev.upper(), node, title)), "node": node, "source": source}
    x = None
    if (x := re.match(r"WEB_ATTACK (\S+) (?:web attack: (.+)|http-flood (.+)|linked to the file change.*)$", rest)):
        return ev("high", "Web attack %s from %s - blocked" % (x.group(2) or ("HTTP flood" if x.group(3) else "web shell source"), x.group(1)))
    if (x := re.match(r"WEB_RESTORED (\S+)", rest)): return ev("high", "Defaced web file restored from the clean snapshot: %s" % x.group(1))
    if (x := re.match(r"WEB_QUARANTINED (\S+)", rest)): return ev("critical", "Web shell quarantined: %s" % x.group(1))
    if (x := re.match(r"HOST_ATTACK HIGH pid=(\d+) (.+?) \| (.*?) \| (.*)$", rest)): return ev("critical", "%s (pid %s) - %s" % (x.group(2), x.group(1), x.group(4) or "no action"))
    if (x := re.match(r"NODEWATCH_ALERT (CRITICAL|HIGH|MEDIUM|INFO) (.*)$", rest)): return ev(x.group(1).lower(), "Host change: " + x.group(2))
    if rest.startswith("BLOCKKEEPER_TAMPER"): return ev("high", "Firewall tampering undone: " + rest[len("BLOCKKEEPER_TAMPER "):])
    if "KILL_TRIGGER" in rest: return ev("critical", "Ransomware: the attacking process was killed")
    if (x := re.match(r"RANSOM_TYPE (\S+)", rest)): return ev("critical", "Ransomware type: " + x.group(1))
    if rest.startswith("GATE_TRIPPED"): return ev("high", "Ransomware gate tripped: " + rest[len("GATE_TRIPPED "):])
    if rest.startswith("CONTAIN_RUN"): return ev("high", "Network quarantine applied on the target")
    if rest.startswith("VAULT_VERIFY_FAIL"): return ev("critical", "Vault verification FAILED: " + rest[len("VAULT_VERIFY_FAIL "):])
    if (x := re.match(r"TRUST (\S+) -> (SUSPEND|WATCH)", rest)): return ev("high" if x.group(2) == "SUSPEND" else "medium", "Peer %s is now %s (trust score)" % (x.group(1), x.group(2)))
    if rest.startswith("TRUST ALERT") or rest.startswith("ALERT "): return ev("high", rest[:200])
    return None


def new_lines(prev, cur):
    """Log tails slide: the new lines are what comes after the longest overlap of the end of prev with the start of cur."""
    for k in range(min(len(prev), len(cur)), 0, -1):
        if prev[-k:] == cur[:k]: return cur[k:]
    return cur


class Notifier:
    def __init__(self, senders, min_sev="high", max_per_min=10, now=time.time, log=print):
        self.senders, self.min, self.max, self.now, self.log = senders, RANK.get(min_sev, 2), max_per_min, now, log
        self.prev = {}; self.sent = collections.deque(); self.first = set()
    def poll(self, collect, replay=False):
        """collect() -> {(node, source): [lines]}. Returns the events that were turned into messages."""
        out = []
        for key, lines in collect().items():
            prev = self.prev.get(key)
            fresh = lines if (prev is not None or replay) else []          # the first look at a log is only a baseline
            if prev is not None: fresh = new_lines(prev, lines)
            self.prev[key] = list(lines)
            for l in fresh:
                e = parse(l, key[0], key[1])
                if e and RANK[e["sev"]] >= self.min: out.append(e)
        self.deliver(out); return out
    def deliver(self, events):
        t = self.now()
        while self.sent and t - self.sent[0] > 60: self.sent.popleft()
        room = max(0, self.max - len(self.sent)); now_send, rest = events[:room], events[room:]
        for e in now_send: self.sent.append(t); self.fan("DualShield " + e["text"])
        if rest: self.sent.append(t); self.fan("DualShield: +%d more alerts in the last minute (see the dashboard, tab Attack events)" % len(rest))
    def fan(self, text):
        for name, fn in self.senders:
            try: fn(text)
            except Exception as ex: self.log("ALERT_SEND_FAILED %s: %s" % (name, str(ex)[:120]))


def telegram(token, chat):
    def send(text):
        req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % token, data=json.dumps({"chat_id": chat, "text": text}).encode(), headers={"content-type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    return send


def webhook(url):
    def send(text):
        req = urllib.request.Request(url, data=json.dumps({"text": text, "content": text}).encode(), headers={"content-type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    return send


def email(c):
    def send(text):
        m = EmailMessage(); m["Subject"] = text[:90]; m["From"] = c.get("ALERT_MAIL_FROM") or c.get("ALERT_SMTP_USER", "dualshield@localhost"); m["To"] = c["ALERT_MAIL_TO"]; m.set_content(text)
        with smtplib.SMTP(c["ALERT_SMTP_HOST"], int(c.get("ALERT_SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            if c.get("ALERT_SMTP_USER"): s.login(c["ALERT_SMTP_USER"], c.get("ALERT_SMTP_PASS", ""))
            s.send_message(m)
    return send


def senders_from(c):
    out = []
    if c.get("ALERT_TELEGRAM_TOKEN") and c.get("ALERT_TELEGRAM_CHAT"): out.append(("telegram", telegram(c["ALERT_TELEGRAM_TOKEN"], c["ALERT_TELEGRAM_CHAT"])))
    if c.get("ALERT_SMTP_HOST") and c.get("ALERT_MAIL_TO"): out.append(("email", email(c)))
    if c.get("ALERT_WEBHOOK"): out.append(("webhook", webhook(c["ALERT_WEBHOOK"])))
    return out


def real_collect(c):
    sources = [("web", 80), ("host", 80), ("nodewatch", 80), ("keeper", 80)]
    def agent_lines(role, name, n):
        try:
            r = subprocess.run([sys.executable, os.path.join(HERE, "agent_call.py"), role, "GET", "/log?name=%s&n=%d" % (name, n)], capture_output=True, text=True, timeout=20, env=dict(os.environ, **{k: v for k, v in c.items() if k.startswith("AGENT_SECRET") or k in ("T_IP", "P_IP", "TLS")}))
            return json.loads(r.stdout).get("lines", []) if r.returncode == 0 else []
        except Exception: return []
    def collect():
        out = {}
        for role, node in (("T", "T"), ("P", "P")):
            for name, n in sources + ([("watch", 80)] if role == "T" else []): out[(node, name)] = agent_lines(role, name, n)
        try: out[("D", "trust")] = open(os.path.join(HERE, "logs", "peer_trust.out"), errors="replace").read().splitlines()[-80:]
        except OSError: out[("D", "trust")] = []
        return out
    return collect


if __name__ == "__main__":
    c = cfg(); senders = senders_from(c)
    if not senders: sys.exit("No channel set. Put ALERT_TELEGRAM_TOKEN + ALERT_TELEGRAM_CHAT, or ALERT_SMTP_*, or ALERT_WEBHOOK in multi/config.env")
    dry = "--dry-run" in sys.argv
    if dry: senders = [("print", lambda t: print("WOULD SEND:", t))]
    if "--test" in sys.argv:
        for name, fn in senders:
            try: fn("DualShield test alert: this channel works."); print("sent via", name)
            except Exception as ex: print("FAILED via %s: %s" % (name, ex))
        sys.exit(0)
    n = Notifier(senders, c.get("ALERT_MIN", "high").lower(), int(c.get("ALERT_MAX_PER_MIN", "10")), log=lambda m: print(time.strftime("%H:%M:%S ") + m, flush=True))
    collect = real_collect(c); every = float(c.get("ALERT_EVERY", "10"))
    print("ALERT_NOTIFY on: %s, minimum severity %s" % (", ".join(x[0] for x in senders), c.get("ALERT_MIN", "high")), flush=True)
    while True:
        try: n.poll(collect)
        except Exception as ex: print("ALERT_NOTIFY error: %s" % ex, flush=True)
        time.sleep(every)
