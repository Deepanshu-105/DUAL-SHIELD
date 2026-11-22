#!/usr/bin/env python3
"""v13.13 on a REAL running Fabric network + gateway (like fabric/test_fabric.py):
 1 minOrgs=2: two nodes of ONE organisation cannot confirm a threat; a node of the other organisation completes it
 2 a slashed node leaves the quorum count (nodeCount)
 3 peer_trust.py: a node that reports an address of our own infrastructure is revoked at once"""
import json, os, random, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "..", "network"))
from chainlib import Chain, ChainError, IDENTITY_NAMES
import ipcrypt
c = Chain(); bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
def tolerant(f, *a):
    try: return f(*a)
    except ChainError as e: return str(e)
for who in (1, 2, 3):
    node = IDENTITY_NAMES[who]
    if not c.query(0, "nodeInfo", node)["approved"]: c.submit(0, "addNode", node)
    if c.query(0, "nodeInfo", node)["stake"] == 0: tolerant(c.register_node, who)
p = c.params(); check("params report minOrgs (default 1)", p.get("minOrgs") == 1)
c.submit(0, "propose", 11, "", "", 2); check("governance can set minOrgs=2", c.params()["minOrgs"] == 2)
ip = "198.51.100.%d" % random.randint(100, 200); e = ipcrypt.encode(ip)
c.submit(1, "reportThreat", e, "t"); r = json.loads(c.submit(3, "reportThreat", e, "t"))
check("two nodes of the SAME organisation do not confirm (count 2, K=2)", r["count"] == 2 and r["confirmed"] is False)
r = json.loads(c.submit(2, "reportThreat", e, "t")); check("a node of the OTHER organisation completes the confirmation", r["confirmed"] is True)
c.submit(0, "propose", 11, "", "", 1); check("minOrgs back to 1", c.params()["minOrgs"] == 1)
# 2: slash keeps nodeCount honest (takes about 65 s: the report window)
ip2 = "198.51.100.%d" % random.randint(1, 90); e2 = ipcrypt.encode(ip2); n0 = c.params()["nodeCount"]
c.submit(3, "reportThreat", e2, "t"); print("waiting for the 60 s window ..."); time.sleep(63)
c.submit(0, "slashExpired", e2); n1 = c.params()["nodeCount"]
check("after the slash the node no longer counts for the quorum (%d -> %d)" % (n0, n1), n1 == n0 - 1)
tolerant(c.register_node, 3)
# 3: infrastructure framing -> revoke
frame = "203.0.113.%d" % random.randint(1, 254); e3 = ipcrypt.encode(frame); head0 = c.events(0, 1)[1]
c.submit(3, "reportThreat", e3, "frame")
env = dict(os.environ, D_IP=frame, TRUST_FILE="/tmp/pt_state_%d.json" % os.getpid(), TRUST_AUDIT="/tmp/pt_audit.log")
out = subprocess.run([sys.executable, os.path.join(HERE, "..", "network", "peer_trust.py"), "--once", "--act", "propose", "--from", str(head0)], env=env, capture_output=True, text=True, timeout=120).stdout
check("monitor flagged the node that reported our infrastructure", IDENTITY_NAMES[3] in out and "SUSPEND" in out)
info = c.query(0, "nodeInfo", IDENTITY_NAMES[3]); check("that node is revoked (not approved, stake forfeited)", info["approved"] is False and info["stake"] == 0)
check("the other nodes are untouched", c.query(0, "nodeInfo", IDENTITY_NAMES[1])["approved"] is True)
c.submit(0, "addNode", IDENTITY_NAMES[3]); tolerant(c.register_node, 3)       # leave the network as we found it
print(out[-500:]); sys.exit(1 if bad else 0)
