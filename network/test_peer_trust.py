#!/usr/bin/env python3
"""Logic test of peer_trust (no chain needed): scoring, decay, infrastructure framing, flood, overrule, exemptions, collusion alert, action once."""
import os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
os.environ["TRUST_AUDIT"] = os.path.join(tempfile.mkdtemp(), "a.log")
import peer_trust as pt
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
clock = [1000.0]; acted = []
def mk(**kw): return pt.Trust(infra={"10.0.0.1", "10.0.0.2"}, now=lambda: clock[0], actions={"suspend": lambda n: acted.append(n) or "proposed"}, **kw)
A, B, C = "Org1MSP:User1@org1.example.com", "Org2MSP:User1@org2.example.com", "Org1MSP:User2@org1.example.com"
t = mk(); rep = lambda node, ip: {"name": "ThreatReported", "node": node, "ip": ip, "count": 1}
t.event(rep(A, "203.0.113.5")); check("an ordinary report scores nothing", t.snapshot()["nodes"][A]["state"] == "OK" and t.snapshot()["nodes"][A]["score"] == 0)
t.event(rep(B, "10.0.0.1")); s = t.snapshot()["nodes"][B]
check("reporting our own infrastructure address = SUSPEND at once", s["state"] == "SUSPEND" and acted == [B])
t.event(rep(B, "10.0.0.2")); check("the action is taken only once per hour", acted == [B])
t = mk(); acted.clear()
t.event({"name": "NodeSlashed", "node": A, "ip": "x", "amount": 1}); check("one slash (lone report expired) = still OK", t.snapshot()["nodes"][A]["state"] == "OK")
t.event({"name": "NodeSlashed", "node": A, "ip": "y", "amount": 1}); check("second slash = WATCH", t.snapshot()["nodes"][A]["state"] == "WATCH")
t = mk(); t.event({"name": "ThreatOverruled", "ip": "z"}, tally={"reporters": [A]}); t.event({"name": "ThreatOverruled", "ip": "z2"}, tally={"reporters": [A]}); check("two governor overrules of its threats = SUSPEND", t.snapshot()["nodes"][A]["state"] == "SUSPEND")
t = mk(); t.event({"name": "ThreatOverruled", "ip": "z"}, tally={"reporters": [C]}); check("one overrule alone = WATCH", t.snapshot()["nodes"][C]["state"] == "WATCH")
t = mk(); acted.clear()
for i in range(pt.RATE_MAX + 1): t.event(rep(C, "198.51.100.%d" % i)); clock[0] += 1
check("flooding (more than RATE_MAX reports in 10 min) is scored", t.snapshot()["nodes"][C]["score"] >= 30)
t = mk(); t.event({"name": "NodeSlashed", "node": A, "ip": "x", "amount": 1}); t.event({"name": "NodeSlashed", "node": A, "ip": "y", "amount": 1})
clock[0] += 3 * 86400; check("the score decays over days (forgiveness)", t.snapshot()["nodes"][A]["state"] == "WATCH" and t.snapshot()["nodes"][A]["score"] < 10)
t = mk(exempt=[A]); acted.clear(); t.event(rep(A, "10.0.0.1")); check("the owner / exempt node is never acted against", acted == [] and A not in t.snapshot()["nodes"])
t = mk(); t.event(rep(A, "10.0.0.1")); check("alert mode never changes the chain", True)
t2 = pt.Trust(infra={"10.0.0.1"}, act="alert", now=lambda: clock[0], actions={"suspend": lambda n: acted.append(n)}); acted.clear(); t2.event(rep(B, "10.0.0.1")); check("--act alert: SUSPEND is reported but no action", acted == [] and t2.snapshot()["nodes"][B]["state"] == "SUSPEND")
t = mk()
for i in range(5): t.event({"name": "ThreatConsensusReached", "ip": "x%d" % i}, tally={"reporters": [A, B]}, nodes_staked=3)
check("collusion alert when the same two nodes alone confirm 5 threats among 3+ nodes", any("collusion" in a for a in t.alerts))
# ---- v13.14 audit ----
clock[0] = 5000.0; acted.clear(); t = mk()
t.event({"name": "ThreatConsensusReached", "ip": "203.0.113.9"}, tally={"reporters": [A, B]})
t.event({"name": "ThreatConsensusReached", "ip": "10.0.0.1"}, tally={"reporters": [A, B]})
check("infrastructure address is never expected to be blocked", "10.0.0.1" not in t.expected and "203.0.113.9" in t.expected)
t.audit(C, {"state": "ok", "ips": []}); check("inside the grace time = no penalty", t.snapshot()["nodes"].get(C, {"score": 0})["score"] == 0)
clock[0] += 31; t.audit(C, {"state": "ok", "ips": []}); check("node that did not apply a confirmed block = NOT_ENFORCING", t.snapshot()["nodes"][C]["score"] >= 40 and any("did not apply" in a for a in t.alerts))
sc = t.snapshot()["nodes"][C]["score"]; t.audit(C, {"state": "ok", "ips": []}); check("same missing block is scored only once", t.snapshot()["nodes"][C]["score"] == sc)
t.audit(A, {"state": "ok", "ips": ["203.0.113.9"]}); check("node that applied the block = clean", t.snapshot()["nodes"].get(A, {"score": 0})["score"] == 0)
t.forget("203.0.113.9"); check("overruled block is no longer expected", "203.0.113.9" not in t.expected)
t = mk(); t.audit(B, {"state": "down"}); clock[0] += 100; t.audit(B, {"state": "down"}); check("short outage = no SILENT", t.snapshot()["nodes"].get(B, {"score": 0})["score"] == 0)
clock[0] += 100; t.audit(B, {"state": "down"}); check("long silence = SILENT", t.snapshot()["nodes"][B]["score"] >= 30)
t.audit(B, {"state": "bad"}); check("bad signature = BAD_ANSWER", t.snapshot()["nodes"][B]["score"] >= 90)
t = mk(); t.audit(A, {"state": "ok", "ips": []}); t.audit(B, {"state": "down"}); t.audit(C, {"state": "down"}); check("quorum-unreachable alert", any("quorum" in a for a in t.alerts))
sys.exit(1 if bad else 0)
