#!/usr/bin/env python3
"""Tests for peer discovery: signed registration, replay, hijack and rate limits, and a live client/server round trip."""
import json, os, subprocess, sys, tempfile, threading, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import registry, join
from http.server import ThreadingHTTPServer
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)

ST, SP = "T-secret-0123456789abcdef", "P-secret-0123456789abcdef"
tmp = tempfile.mkdtemp()
now = [1000.0]
logs = []
R = registry.Registry({"target": ST, "peer": SP}, path=os.path.join(tmp, "peers.json"), ttl=120, rate=100, clock=lambda: now[0], log=logs.append)
def reg(role, src, secret, name="t1", ts=None, nonce="n1", sig=None):
    ts = str(int(now[0])) if ts is None else str(ts)
    sig = sig or registry.sign(secret, "register", role, name, ts, nonce)
    return R.register(role, src, name, ts, nonce, sig)
def peers(role, secret, src="10.0.0.9", ts=None, nonce="p1", sig=None):
    ts = str(int(now[0])) if ts is None else str(ts)
    return R.peers(role, src, ts, nonce, sig or registry.sign(secret, "peers", role, ts, nonce))

c, o, _ = reg("target", "10.0.0.11", ST)
check("valid registration accepted, address = source", c == 200 and o["ip"] == "10.0.0.11", o)
c, o, _ = reg("target", "10.0.0.11", ST, nonce="n1")
check("replayed nonce refused", c == 401, (c, o))
c, o, _ = reg("target", "10.0.0.11", "x" * 24, nonce="n2")
check("wrong secret refused", c == 401, (c, o))
c, o, _ = reg("target", "10.0.0.11", ST, nonce="n3", ts=900)
check("stale timestamp refused", c == 401, (c, o))
c, o, _ = reg("attacker", "10.0.0.66", ST, nonce="n4")
check("unknown role refused", c == 403, (c, o))
c, o, _ = reg("target", "10.0.0.11", ST, name="bad name!", nonce="n5")
check("bad name refused", c == 400, (c, o))
c, o, _ = reg("peer", "10.0.0.12", SP, name="p1", nonce="n6")
check("peer registers", c == 200)
c, o, _ = reg("peer", "10.0.0.66", SP, name="p1", nonce="n7")
check("live role cannot be taken over from another address (stolen key)", c == 409, (c, o))
check("conflict is logged", any("REGISTRY_CONFLICT" in l for l in logs))
now[0] += 200
c, o, _ = reg("peer", "10.0.0.77", SP, name="p1", nonce="n8")
check("after heartbeat expiry the role may move (DHCP change)", c == 200 and o["ip"] == "10.0.0.77", (c, o))
c, o, _ = peers("target", ST, nonce="q1")
check("authenticated peer sees the table", c == 200 and o["peers"]["peer"]["ip"] == "10.0.0.77" and not o["peers"]["target"]["online"], o)
c, o, _ = peers("target", "y" * 24, nonce="q2")
check("table hidden from unauthenticated callers", c == 401)
saved = json.load(open(os.path.join(tmp, "peers.json")))
check("table persisted with mode 600", saved["peers"]["peer"]["ip"] == "10.0.0.77" and oct(os.stat(os.path.join(tmp, "peers.json")).st_mode & 0o777) == "0o600")
R2 = registry.Registry({"target": ST, "peer": SP}, path=os.path.join(tmp, "peers.json"), clock=lambda: now[0], log=logs.append)
check("table survives a restart", R2.table.get("peer", {}).get("ip") == "10.0.0.77")
RL = registry.Registry({"target": ST}, path=os.path.join(tmp, "rl.json"), rate=5, clock=lambda: now[0], log=lambda m: None)
codes = [RL.register("target", "10.0.0.50", "t", str(int(now[0])), "r%d" % i, "bad")[0] for i in range(8)]
check("rate limit per source", 429 in codes, codes)

# live round trip: real HTTP server + real join client
os.environ["PEERS_FILE"] = os.path.join(tmp, "live.json")
live = registry.Registry({"target": ST, "peer": SP}, path=os.path.join(tmp, "live.json"), log=lambda m: None)
registry.H.reg = live
srv = ThreadingHTTPServer(("127.0.0.1", 0), registry.H); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d" % port
env = dict(os.environ, D_IP="127.0.0.1", REGISTRY_PORT=str(port), PEERS_ENV=os.path.join(tmp, "peers.env"))
def run(role, secret, *a):
    return subprocess.run([sys.executable, os.path.join(HERE, "join.py"), *a], env=dict(env, ROLE=role, AGENT_SECRET=secret), capture_output=True, text=True, timeout=30)
r = run("target", ST, "--once")
check("client joins (T)", r.returncode == 0 and "JOIN_OK" in r.stdout, r.stdout + r.stderr)
r = run("peer", SP, "--once")
check("client joins (P) and learns T", r.returncode == 0 and "T_IP=127.0.0.1" in r.stdout, r.stdout + r.stderr)
check("peers.env written", "T_IP=127.0.0.1" in open(os.path.join(tmp, "peers.env")).read())
r = run("target", "z" * 24, "--once")
check("client with wrong secret fails", r.returncode == 1 and "JOIN_FAIL" in r.stdout, r.stdout)
r = subprocess.run([sys.executable, os.path.join(HERE, "join.py"), "--once"], env=dict(env, ROLE="target", AGENT_SECRET=ST, D_IP="127.0.0.1", REGISTRY_PORT="1"), capture_output=True, text=True, timeout=30)
check("unreachable registry fails cleanly", r.returncode == 1 and "JOIN_FAIL" in r.stdout, r.stdout + r.stderr)
# a fake registry that says "200 ok" but cannot sign the answer must be detected by the client
from http.server import BaseHTTPRequestHandler
class FakeH(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        b = b'{"ok": true, "ip": "1.2.3.4"}'
        self.send_response(200); self.send_header("content-length", str(len(b))); self.send_header("X-Resp-Sig", "00"); self.end_headers(); self.wfile.write(b)
fsrv = ThreadingHTTPServer(("127.0.0.1", 0), FakeH); threading.Thread(target=fsrv.serve_forever, daemon=True).start()
try:
    join.call("http://127.0.0.1:%d" % fsrv.server_address[1], ST, "POST", "/register", "target", {"name": "x"})
    check("forged 200 answer from an impostor registry is rejected", False)
except ValueError:
    check("forged 200 answer from an impostor registry is rejected", True)
print("ALL PASS" if not bad else "SOME FAILED: %s" % bad); sys.exit(1 if bad else 0)
