#!/usr/bin/env python3
"""v13.22: (1) "Incident report" button on the Attack events tab, (2) alerts started by multi/start_D.sh, (3) alert keys kept secret by protect_config.sh.
Run from the repo root:  python3 apply_v13_22.py    Needs v13.21 first. Nothing is changed unless every anchor matches (*.bak kept)."""
import os, sys
HOOK = '''if grep -Eq '^[[:space:]]*(ALERT_TELEGRAM_TOKEN|ALERT_WEBHOOK|ALERT_SMTP_HOST)=[^[:space:]#]' "$ROOT/multi/config.env" 2>/dev/null; then   # v13.22 alerts
  pkill -f multi/alert_notify.py 2>/dev/null
  nohup python3 -u "$ROOT/multi/alert_notify.py" > $LOGD/alert_notify.out 2>&1 &
  echo "Alerts:    on (log $LOGD/alert_notify.out)"
fi
'''
FILES = {
 "dashboard/app/EventsPanel.jsx": [('    <div className="grid" style={{ marginTop: 12 }}>', '    <div style={{ marginTop: 10 }}><a className="tab" href="/api/report" target="_blank" rel="noreferrer">Incident report (print / PDF)</a></div>\n    <div className="grid" style={{ marginTop: 12 }}>', "/api/report")],
 "multi/start_D.sh": [('SCHEME=http; [ "${TLS:-0}" = "1" ] && SCHEME=https\n', HOOK + 'SCHEME=http; [ "${TLS:-0}" = "1" ] && SCHEME=https\n', "v13.22 alerts")],
}
OPTIONAL = {"multi/protect_config.sh": ("DASH_SESSION_KEY|SELFGUARD_KEY|CHAIN_IP_KEY'", "DASH_SESSION_KEY|SELFGUARD_KEY|CHAIN_IP_KEY|ALERT_TELEGRAM_TOKEN|ALERT_SMTP_PASS|ALERT_WEBHOOK'", "ALERT_TELEGRAM_TOKEN")}
new, bad = {}, []
for p, edits in FILES.items():
    if not os.path.exists(p): bad.append("%s missing (v13.21 applied? run from the repo root?)" % p); continue
    s = open(p).read(); o = s
    for a, b, mark in edits:
        if mark in s: continue
        if s.count(a) != 1: bad.append("%s: anchor not found: %s" % (p, a[:50])); continue
        s = s.replace(a, b, 1)
    new[p] = (o, s)
p = "multi/protect_config.sh"
if os.path.exists(p):
    s = open(p).read(); a, b, mark = OPTIONAL[p]
    if mark not in s:
        if s.count(a) < 1: bad.append("%s: KEYS line not found" % p)
        else: new[p] = (s, s.replace(a, b))
if bad: print("NOTHING CHANGED:\n  " + "\n  ".join(bad)); sys.exit(1)
for p, (o, s) in new.items():
    if s != o: open(p + ".bak", "w").write(o); open(p, "w").write(s); print("patched", p)
    else: print("already up to date:", p)
for f in ("multi/alert_notify.py", "dashboard/lib/report.js", "dashboard/app/api/report/route.js"): print(("ok " if os.path.exists(f) else "MISSING ") + f)
print("v13.22 applied. Test: python3 multi/test_alert_notify.py ; node dashboard/test_report.mjs ; send a test alert: python3 multi/alert_notify.py --test")
