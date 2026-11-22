#!/usr/bin/env python3
"""Logic test of block_policy: infrastructure is never blocked, TTL for evidence-less blocks, circuit breaker, restart keeps expiries."""
import os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import block_policy as bp
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
blocked, freed, clock = [], [], [1000.0]
f = os.path.join(tempfile.mkdtemp(), "p.json")
mk = lambda **kw: bp.Policy(blocked.append, lambda ip, why="ttl": freed.append(ip), infra={"10.0.0.1"}, now=lambda: clock[0], log=lambda m: None, state_file=f, **kw)
p = mk(ttl=100, cb_max=3, cb_win=60)
for ip in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1"): p.consensus(ip, False)
check("infrastructure, loopback, link-local and multicast are refused", blocked == [])
check("an ordinary address is blocked", p.consensus("203.0.113.5", False) == "BLOCKED" and blocked == ["203.0.113.5"])
p.consensus("203.0.113.6", True)
clock[0] += 101; gone = p.tick()
check("a block without local evidence expires after the TTL", gone == ["203.0.113.5"] and freed == ["203.0.113.5"])
check("a block WITH local evidence stays", "203.0.113.6" not in freed)
p2 = mk(ttl=100, cb_max=3, cb_win=60); p2.consensus("203.0.113.7", False)
p3 = mk(ttl=100, cb_max=3, cb_win=60); clock[0] += 101
check("expiry survives a restart (state file)", "203.0.113.7" in p3.tick())
q = mk(ttl=0, cb_max=3, cb_win=60); blocked.clear(); clock[0] += 1000
r = [q.consensus("198.51.100.%d" % i, False) for i in range(1, 6)]
check("circuit breaker: the 4th and 5th new block within the window are held", r == ["BLOCKED"] * 3 + ["HELD"] * 2)
check("held, but an address this node saw itself is still blocked", q.consensus("198.51.100.99", True) == "BLOCKED")
clock[0] += 61; check("the breaker closes after the window", q.consensus("198.51.100.77", False) == "BLOCKED")
q.release("198.51.100.77"); check("overrule removes the expiry", "198.51.100.77" not in q.exp)
check("local_infra() finds at least this machine", len(bp.local_infra()) >= 1)
sys.exit(1 if bad else 0)
