#!/usr/bin/env python3
"""v13.19: wires node_watch into T and P. Run from the repo root AFTER v13.16:  python3 apply_v13_19.py
Every anchor is checked first; if one does not match NOTHING is changed. Originals are kept as *.bak."""
import sys, os
NW = '''pkill -f multi/node_watch.py 2>/dev/null
[ -s /var/lib/dualshield/nodewatch.baseline.json ] || "$PY" "$ROOT/multi/node_watch.py" --init      # baseline = this (clean) node
nohup "$PY" -u "$ROOT/multi/node_watch.py" > /var/log/nodewatch.out 2>&1 &     # NODEWATCH_ALERT lines: new port / uid-0 / keys / cron / module ...
'''
EDITS = {
 "multi/agent.py": [('    "keeper": shield_os.log_path("keeper.log"),', '    "keeper": shield_os.log_path("keeper.log"),\n    "nodewatch": shield_os.log_path("nodewatch.log"),', '"nodewatch"')],
 "multi/start_T.sh": [('AGENT_ALLOW_V=""; [ "${PRODUCTION:-0}" = "1" ]', NW + 'AGENT_ALLOW_V=""; [ "${PRODUCTION:-0}" = "1" ]', "node_watch.py")],
 "multi/start_P.sh": [('PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW=', NW + 'PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW=', "node_watch.py")],
 "multi/check_T.py": [('"PRODUCTION=1 or KEEP_BLOCKS=1, then multi/start_T.sh")',
   '"PRODUCTION=1 or KEEP_BLOCKS=1, then multi/start_T.sh")\nadd("PASS" if running("multi/node_watch.py") else ("FAIL" if prod else "WARN"), "node_watch running (new ports, accounts, keys, cron, modules)", "multi/start_T.sh / start_P.sh start it; baseline: python3 multi/node_watch.py --init")', "node_watch running")],
}
new, bad = {}, []
for path, edits in EDITS.items():
    if not os.path.exists(path): bad.append("%s: not found (run from the repo root; v13.16 must be installed)" % path); continue
    s = open(path).read()
    for a, b, mark in edits:
        if mark in s: continue
        if s.count(a) != 1: bad.append("%s: anchor not found: %r" % (path, a[:50])); continue
        s = s.replace(a, b, 1)
    new[path] = s
if bad: print("NOTHING CHANGED:\n  " + "\n  ".join(bad)); sys.exit(1)
for path, s in new.items():
    if s != open(path).read():
        open(path + ".bak", "w").write(open(path).read()); open(path, "w").write(s); print("patched", path)
    else: print("already up to date", path)
print("v13.19 applied. Restart T and P (start_T.sh / start_P.sh). After a change YOU made: python3 multi/node_watch.py --accept")
