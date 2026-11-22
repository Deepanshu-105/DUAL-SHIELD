#!/usr/bin/env python3
"""Rotate dashboard secrets without showing them. Changes multi/config.env in place (mode 600).
   python3 multi/rotate_secrets.py --session          new DASH_SESSION_KEY: every signed-in browser is logged out
   python3 multi/rotate_secrets.py --password admin   ask for a new administrator password (hidden input); also: operator, viewer
   python3 multi/rotate_secrets.py --agents           new AGENT_SECRET_T / AGENT_SECRET_P: then copy each to its laptop and restart T and P
Restart the dashboard afterwards."""
import getpass, os, re, secrets, stat, sys
CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.env")
if not os.path.exists(CFG): sys.exit("multi/config.env not found")
txt = open(CFG).read()
def put(name, val):
    global txt
    line = "%s=%s" % (name, val)
    txt = re.sub(r"^%s=.*$" % name, lambda _: line, txt, flags=re.M) if re.search(r"^%s=" % name, txt, re.M) else txt.rstrip("\n") + "\n" + line + "\n"
new = lambda n=24: secrets.token_urlsafe(n)[:n]
a = sys.argv[1:]
if not a: sys.exit(__doc__)
if "--session" in a: put("DASH_SESSION_KEY", new(32)); print("DASH_SESSION_KEY rotated: all dashboard sessions are now invalid")
if "--agents" in a:
    put("AGENT_SECRET_T", new(32)); put("AGENT_SECRET_P", new(32))
    print("AGENT_SECRET_T / AGENT_SECRET_P rotated. Copy the new value of each into multi/config.env on T and on P (T keeps only _T, P only _P), then restart T, P and the dashboard.")
if "--password" in a:
    who = a[a.index("--password") + 1] if len(a) > a.index("--password") + 1 else ""
    name = {"admin": "DASH_PASS", "operator": "DASH_OPERATOR_PASS", "viewer": "DASH_VIEW_PASS"}.get(who) or sys.exit("use --password admin|operator|viewer")
    p1 = getpass.getpass("new %s password (min 10 characters): " % who); p2 = getpass.getpass("again: ")
    if p1 != p2 or len(p1) < 10: sys.exit("not changed: passwords differ or are shorter than 10 characters")
    others = [m.group(1) for n in ("DASH_PASS", "DASH_OPERATOR_PASS", "DASH_VIEW_PASS") if n != name for m in [re.search(r"^%s=(.*)$" % n, txt, re.M)] if m]
    if p1 in others: sys.exit("not changed: that password is already used by another dashboard account")
    put(name, p1); print(name + " changed")
open(CFG, "w").write(txt); os.chmod(CFG, stat.S_IRUSR | stat.S_IWUSR)
