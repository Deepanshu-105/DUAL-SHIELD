#!/usr/bin/env python3
"""Run this on ANOTHER laptop (for example P): it checks the dashboard on D every 30 s and shouts when D stops answering or answers wrongly.
An attacker with root on D can stop the dashboard but cannot stop this alarm. Stdlib only.
   python3 multi/watch_dashboard.py --url https://D_IP:3443/login --cafile multi/tls/node/ca.crt [--interval 30] [--fails 3] [--webhook https://...] [--once]
   (plain lab: --url http://D_IP:3000/login). Alerts go to the screen and to multi/logs/watch_dashboard.log; --webhook also POSTs them."""
import argparse, json, os, socket, ssl, sys, time, urllib.request
ap = argparse.ArgumentParser()
ap.add_argument("--url", required=True); ap.add_argument("--cafile"); ap.add_argument("--interval", type=int, default=30)
ap.add_argument("--fails", type=int, default=3); ap.add_argument("--webhook"); ap.add_argument("--once", action="store_true"); ap.add_argument("--print-autostart", action="store_true")
a = ap.parse_args()
if a.print_autostart:      # v13.11: run the watcher by itself on another laptop so nobody has to remember to start it
    me = os.path.abspath(__file__); cmd = "%s %s --url %s%s --interval %d --fails %d%s" % (sys.executable, me, a.url, " --cafile " + a.cafile if a.cafile else "", a.interval, a.fails, " --webhook " + a.webhook if a.webhook else "")
    print("# Linux (crontab -e): starts at boot and again every 10 minutes if it is not running\n@reboot " + cmd + " >> /tmp/watch_dashboard.out 2>&1 &\n*/10 * * * * pgrep -f watch_dashboard.py >/dev/null || (" + cmd + " >> /tmp/watch_dashboard.out 2>&1 &)\n")
    print("# Windows (Administrator PowerShell): starts at boot\nschtasks /Create /TN DualShieldWatcher /SC ONSTART /RU SYSTEM /TR \"" + cmd + "\"")
    sys.exit(0)
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "watch_dashboard.log"); os.makedirs(os.path.dirname(LOG), exist_ok=True)
ctx = ssl.create_default_context(cafile=a.cafile) if a.url.startswith("https") else None
def say(level, msg):
    line = "%s %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg); print(line, flush=True)
    try: open(LOG, "a").write(line + "\n")
    except OSError: pass
    if a.webhook and level != "OK":
        try: urllib.request.urlopen(urllib.request.Request(a.webhook, json.dumps({"text": line}).encode(), {"content-type": "application/json"}), timeout=5)
        except Exception: pass
def probe():
    try:
        r = urllib.request.urlopen(a.url, timeout=8, context=ctx); body = r.read(20000).decode("utf8", "replace")
        if r.status != 200: return "HTTP %d" % r.status
        if "Dual-Shield" not in body: return "answers, but this is not the Dual-Shield login page"
        return None
    except urllib.error.HTTPError as e: return "HTTP %d" % e.code
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError) as e: return "unreachable: %s" % getattr(e, "reason", e)
bad, down = 0, False
while True:
    err = probe()
    if err:
        bad += 1
        if bad >= a.fails and not down: down = True; say("ALERT", "dashboard on D is DOWN or wrong after %d checks: %s" % (bad, err))
        elif not down: say("WARN", "check %d/%d failed: %s" % (bad, a.fails, err))
    else:
        if down: say("OK", "dashboard is back")
        elif bad: say("OK", "recovered after %d failed check(s)" % bad)
        bad, down = 0, False
        if a.once: say("OK", "dashboard answers")
    if a.once: sys.exit(1 if err else 0)
    time.sleep(a.interval)
