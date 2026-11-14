#!/usr/bin/env python3
"""End-to-end test against a RUNNING Fabric network + gateway (fabric/deploy/network.sh up; node fabric/gateway/server.js):
real transactions endorsed by both organisations, K=2 consensus, slashing rules, governance, the peer listener blocking
an IP, overrule lifting it. Safe to repeat (uses a fresh IP each run).
   GATEWAY_URL=http://127.0.0.1:8600 python3 fabric/test_fabric.py"""
import os, random, shutil, stat, subprocess, sys, tempfile, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "network"))
from chainlib import Chain, ChainError, IDENTITY_NAMES
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)
def raises(fn, text):
    try: fn()
    except ChainError as e: return text in str(e)
    return False

c = Chain()
try:
    c.head()
except Exception as e:
    print("SKIP: no gateway reachable (%s). Start the network and gateway first." % e); sys.exit(0)
ip = "198.51.100.%d" % random.randint(10, 250)
ip2 = "203.0.113.%d" % random.randint(10, 250)

p = c.params()
check("chaincode answers and is initialised (K=2, owner is Org1 Admin)", p["K"] == 2 and p["owner"] == IDENTITY_NAMES[0], p)
for who in (1, 2):                                   # idempotent set-up
    try: c.submit(0, "addNode", IDENTITY_NAMES[who])
    except ChainError: pass
    try: c.register_node(who)
    except ChainError as e: assert "already registered" in str(e), e
check("both nodes are staked", all(c.query(0, "nodeInfo", IDENTITY_NAMES[w])["stake"] == 1 for w in (1, 2)))
check("a stranger identity cannot register (not approved)", raises(lambda: c.register_node(3), "not approved"))

c.report_threat(ip, "fp", who=1)
check("one report: counted, not confirmed", c.tally(ip) == {"count": 1, "k": 2, "confirmed": False}, c.tally(ip))
check("same node cannot report twice", raises(lambda: c.report_threat(ip, "fp", who=1), "already reported"))
c.report_threat(ip, "fp", who=2)
check("second node: consensus reached", c.tally(ip)["confirmed"] is True)
bi = c.query(0, "blockInfo", ip)
check("block is active with a confirmation time", bi["active"] and bi["confirmedAt"] > 0, bi)
evs, head = c.events(0)
check("chaincode events carry the consensus", any(e["name"] == "ThreatConsensusReached" and e["ip"] == ip for e in evs))

# the peer listener, as a real process with a fake ipset
tmp = tempfile.mkdtemp(); fb = os.path.join(tmp, "bin"); os.makedirs(fb)
open(os.path.join(fb, "ipset"), "w").write('#!/bin/sh\necho "$@" >> %s/ipset.log\n' % tmp)
os.chmod(os.path.join(fb, "ipset"), 0o755)
env = dict(os.environ, PATH=fb + ":" + os.environ["PATH"], PEER_LOG=os.path.join(tmp, "peer.log"), POLL="0.3")
lp = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "network", "listener.py")], env=env, stdout=open(os.path.join(tmp, "l.out"), "w"), stderr=subprocess.STDOUT)
try:
    time.sleep(2)
    c.report_threat(ip2, "fp", who=1); c.report_threat(ip2, "fp", who=2)
    for _ in range(30):
        time.sleep(0.5)
        if os.path.exists(os.path.join(tmp, "ipset.log")) and ip2 in open(os.path.join(tmp, "ipset.log")).read(): break
    log = open(os.path.join(tmp, "ipset.log")).read() if os.path.exists(os.path.join(tmp, "ipset.log")) else ""
    check("listener blocked the confirmed IP (ipset add)", ("add city_blacklist %s" % ip2) in log, log + open(os.path.join(tmp, "l.out")).read())
    # governance: threshold 1, owner proposes an overrule -> executes at once -> listener unblocks
    gv = subprocess.run([sys.executable, os.path.join(ROOT, "network", "governance.py"), "propose", "overrule", "--ip", ip2], capture_output=True, text=True, env=env)
    check("governance CLI: overrule proposal executed", "EXECUTED" in gv.stdout, gv.stdout + gv.stderr)
    for _ in range(30):
        time.sleep(0.5)
        if ("del city_blacklist %s" % ip2) in open(os.path.join(tmp, "ipset.log")).read(): break
    check("listener lifted the block after the overrule", ("del city_blacklist %s" % ip2) in open(os.path.join(tmp, "ipset.log")).read())
    check("overrule slashed both reporters", all(c.query(0, "nodeInfo", IDENTITY_NAMES[w])["stake"] == 0 for w in (1, 2)))
    for who in (1, 2):                                # restore stake for the next run
        c.register_node(who)
finally:
    lp.terminate(); shutil.rmtree(tmp, ignore_errors=True)

# protected IPs, clean-state anchor
c.submit(0, "propose", 2, "10.99.99.9", "", 0)
check("protected IP cannot be reported", raises(lambda: c.report_threat("10.99.99.9", "fp", who=1), "protected IP"))
c.submit(0, "propose", 3, "10.99.99.9", "", 0)
root = "%064x" % random.getrandbits(256)
c.anchor_clean_state(ip, root, int(time.time()), who=1)
cs = c.clean_state(ip)
check("clean-state root anchored and readable", cs["anchored"] and cs["merkleRoot"] == root, cs)
check("unanchored IP reads as missing", c.clean_state("192.0.2.254")["anchored"] is False)
check("no Ethereum, no gas: the transport is the Fabric gateway", "gas" not in str(c.params()).lower())
print("ALL PASS" if not bad else "SOME FAILED: %s" % bad); sys.exit(1 if bad else 0)
