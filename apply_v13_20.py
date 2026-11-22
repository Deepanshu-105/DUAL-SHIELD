#!/usr/bin/env python3
"""v13.20: starts web_guard and host_guard from T / P and shows them in the agent log list and check_T.
Run from the repo root AFTER v13.16:  python3 apply_v13_20.py     (nothing is changed unless every anchor matches; *.bak kept)"""
import os, sys
START = '''# v13.20: more attacks. web_guard (SQLi/XSS/traversal/RCE/scanners/flood + restore of defaced files, quarantine of web shells), host_guard (reverse shells, miners).
# ON by default with PRODUCTION=1; in the lab: WEB_GUARD=1 / HOST_GUARD=1 in multi/config.env. WEB_LOG = nginx/apache access log, WEB_ROOT = web folder.
pkill -f detector/web_guard.py 2>/dev/null; pkill -f detector/host_guard.py 2>/dev/null
if [ "${WEB_GUARD:-${PRODUCTION:-0}}" = "1" ]; then
  WEB_LOG_V="${WEB_LOG:-$(ls /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null | head -1)}"
  [ -d "${WEB_ROOT:-/var/www/html}" ] && [ ! -d /var/lib/dualshield/web_snapshot ] && "$PY" "$ROOT/detector/web_guard.py" --snapshot
  nohup env WEB_LOG="$WEB_LOG_V" WHITELIST_EXTRA="$D_IP,$P_IP" "$PY" -u "$ROOT/detector/web_guard.py" > /var/log/web_guard.out 2>&1 &
  echo "web guard started (log ${WEB_LOG_V:-none found}, snapshot of ${WEB_ROOT:-/var/www/html})"
fi
if [ "${HOST_GUARD:-${PRODUCTION:-0}}" = "1" ]; then
  nohup env WHITELIST_EXTRA="$D_IP,$P_IP" "$PY" -u "$ROOT/detector/host_guard.py" > /var/log/host_guard.out 2>&1 &
  echo "host guard started (reverse shells, miners)"
fi
'''
EDITS = {  # path: [(anchor, replacement, mark, optional)]
 "multi/start_T.sh": [('echo "T READY:', START + 'echo "T READY:', "host_guard.py", False)],
 "multi/start_P.sh": [('PRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW=', START.split("if [ \"${WEB_GUARD")[0] + 'if [ "${HOST_GUARD:-${PRODUCTION:-0}}" = "1" ]; then\n  nohup env WHITELIST_EXTRA="$D_IP,$T_IP" "$PY" -u "$ROOT/detector/host_guard.py" > /var/log/host_guard.out 2>&1 &\nfi\nPRODUCTION="${PRODUCTION:-0}" AGENT_ALLOW=', "host_guard.py", False)],
 "multi/agent.py": [('    "keeper": shield_os.log_path("keeper.log"),', '    "keeper": shield_os.log_path("keeper.log"),\n    "web": shield_os.log_path("web_guard.out"),\n    "host": shield_os.log_path("host_guard.out"),', '"web": shield_os', False)],
 "multi/check_T.py": [('"PRODUCTION=1 or KEEP_BLOCKS=1, then multi/start_T.sh")', '"PRODUCTION=1 or KEEP_BLOCKS=1, then multi/start_T.sh")\nadd("PASS" if running("detector/host_guard.py") else ("FAIL" if prod else "WARN"), "host_guard running (reverse shells, miners)", "PRODUCTION=1 or HOST_GUARD=1, then multi/start_T.sh")\nadd("PASS" if running("detector/web_guard.py") else "INFO", "web_guard running (only needed if T runs a web server)", "PRODUCTION=1 or WEB_GUARD=1, then multi/start_T.sh")', "host_guard running", False)],
 "run_all_tests.sh": [("detector/test_v5.py; do", "detector/test_v5.py detector/test_web_guard.py detector/test_host_guard.py multi/test_node_watch.py; do", "test_web_guard", True)],
}
new, bad = {}, []
for path, edits in EDITS.items():
    if not os.path.exists(path):
        if all(e[3] for e in edits): continue
        bad.append("%s: not found (run from the repo root; v13.16 must be installed)" % path); continue
    s = open(path).read()
    for a, b, mark, _ in edits:
        if mark in s: continue
        if s.count(a) != 1: bad.append("%s: anchor not found: %r" % (path, a[:50])); continue
        s = s.replace(a, b, 1)
    new[path] = s
if bad: print("NOTHING CHANGED:\n  " + "\n  ".join(bad)); sys.exit(1)
for path, s in new.items():
    if s != open(path).read(): open(path + ".bak", "w").write(open(path).read()); open(path, "w").write(s); print("patched", path)
    else: print("already up to date", path)
print("v13.20 applied. Restart T and P. Web: after a clean deploy run  python3 detector/web_guard.py --snapshot")
