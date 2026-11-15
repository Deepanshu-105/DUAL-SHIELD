#!/usr/bin/env python3
"""v13.7: one node reports -> listener puts the IP on the watchlist -> detector threshold becomes 1 -> second node's report confirms.
Needs a running Fabric network + gateway (see fabric/test_fabric.py). WATCH_FILE is used so nothing else is touched."""
import os, random, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "detector"))
os.environ["WATCH_FILE"] = os.path.join(tempfile.mkdtemp(), "w.json")
os.environ.setdefault("PEER_LOG", os.path.join(tempfile.mkdtemp(), "peer.log"))
import watchlist, ipcrypt
from chainlib import Chain
bad = []
def check(n, ok):
    print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
c = Chain()
try: c.head()
except Exception as e: print("SKIP: no gateway (%s)" % e); sys.exit(0)
ip = "198.51.100.%d" % random.randint(10, 250)
env = dict(os.environ, WATCH_FILE=os.environ["WATCH_FILE"], PEER_LOG=os.environ["PEER_LOG"], DRY="1")
check("not watched at the start", not watchlist.is_watched(ip))
lst = subprocess.Popen([sys.executable, os.path.join(HERE, "listener.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(3)
c.report_threat(ipcrypt.encode(ip), "t", who=1)             # only ONE node has seen it
t0 = time.time()
while time.time() - t0 < 10 and not watchlist.is_watched(ip): time.sleep(0.3)
check("one node's report puts the IP on the watchlist", watchlist.is_watched(ip))
check("not confirmed with a single report", not c.query(0, "getTally", ipcrypt.encode(ip))["confirmed"])
check("this node has no local evidence yet", not watchlist.was_seen(ip))
watchlist.saw(ip)                                            # what ssh_parser does on one failed login
check("local sighting recorded", watchlist.was_seen(ip))
c.report_threat(ipcrypt.encode(ip), "t", who=6 if 6 in [i["who"] for i in c.identities()] else 2)
check("second node's report confirms (K=2)", c.query(0, "getTally", ipcrypt.encode(ip))["confirmed"])
time.sleep(2); lst.terminate(); out = lst.communicate()[0]
check("listener logged WATCH", "WATCH ip=%s" % ip in out)
check("listener logged evidence=local on consensus", "evidence=local" in out)
print(out[-400:]); sys.exit(1 if bad else 0)
