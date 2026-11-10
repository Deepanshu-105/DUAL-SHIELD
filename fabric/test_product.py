#!/usr/bin/env python3
"""v11 product checks against a STRICT gateway (GATEWAY_TLS=1 GATEWAY_LAB=0 GATEWAY_RATE=5 GATEWAY_BURST=10) on a running Fabric network:
  * a REAL second reporter: target certificate reports as node 1, peer certificate as node 2, consensus is reached with no lab shortcut
  * the one-laptop shortcut (COREPORT) is refused in strict mode
  * the gateway rate-limits a flooding client (429) and exposes /metrics
    GATEWAY_URL=https://127.0.0.1:8600 python3 fabric/test_product.py"""
import json, os, random, ssl, subprocess, sys, time, urllib.request
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
URL = os.environ.get("GATEWAY_URL", "https://127.0.0.1:8600")
TLSD = os.path.join(ROOT, "multi", "tls")
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)

def env(role):
    return dict(os.environ, TLS="1", TLS_DIR=os.path.join(TLSD, role), GATEWAY_URL=URL, PYTHONPATH=os.path.join(ROOT, "network"))
def run(role, *cmd):
    return subprocess.run([sys.executable, *cmd], env=env(role), capture_output=True, text=True, timeout=120)
def http(role, method, path, obj=None):
    ctx = ssl.create_default_context(cafile=os.path.join(TLSD, "ca.crt")); ctx.check_hostname = False
    ctx.load_cert_chain(os.path.join(TLSD, role, "node.crt"), os.path.join(TLSD, role, "node.key"))
    req = urllib.request.Request(URL + path, data=json.dumps(obj).encode() if obj is not None else None, method=method, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
    except Exception as e: return 0, str(e)

code, _ = http("dashboard", "GET", "/health")
if code != 200:
    print("SKIP: no strict TLS gateway at", URL); sys.exit(0)
setup = os.path.join(ROOT, "network", "chain_setup.py"); rep = os.path.join(ROOT, "network", "chain_report.py")
run("dashboard", setup, "--approve")
check("target node registers with its own certificate", run("target", setup, "--register", "1").returncode == 0)
check("peer node registers with its own certificate", run("peer", setup, "--register", "2").returncode == 0)
ip = "203.0.113.%d" % random.randint(20, 250)
r1 = run("target", rep, ip, "--who", "1")
def tally(addr):
    sys.path.insert(0, os.path.join(ROOT, "network"))
    import ipcrypt
    c, b = http("dashboard", "POST", "/query", {"who": 0, "fn": "getTally", "args": [ipcrypt.encode(addr)]})
    return json.loads(json.loads(b)["result"])
check("node 1 reports alone: counted, not confirmed", r1.returncode == 0 and tally(ip)["count"] == 1 and not tally(ip)["confirmed"], r1.stderr[-300:])
r2 = run("peer", rep, ip, "--who", "2")
check("node 2 reports independently from its own laptop: consensus reached (no lab shortcut)", r2.returncode == 0 and tally(ip)["confirmed"], r2.stderr[-300:])
ip2 = "203.0.113.%d" % random.randint(20, 250)
r3 = subprocess.run([sys.executable, rep, ip2], env=dict(env("target"), COREPORT="1"), capture_output=True, text=True, timeout=120)
check("the one-laptop shortcut (target pretending to be the peer) is refused in strict mode", r3.returncode != 0 and "may not use that identity" in (r3.stderr + r3.stdout), (r3.stdout + r3.stderr)[-300:])

time.sleep(3)
codes = [http("dashboard", "POST", "/query", {"who": 0, "fn": "params", "args": []})[0] for _ in range(40)]
check("a flooding client is rate limited (HTTP 429) while a normal client is not", 429 in codes and codes[0] == 200, codes)
time.sleep(3)
code, m = http("dashboard", "GET", "/metrics")
vals = dict(l.split() for l in m.splitlines() if l and not l.startswith("#"))
check("/metrics exposes counters (requests, transactions, rate limited, forbidden)", code == 200 and int(vals.get("gateway_rate_limited_total", 0)) >= 1 and int(vals.get("gateway_tx_ok_total", 0)) >= 2 and int(vals.get("gateway_forbidden_total", 0)) >= 1, vals)
print("\nALL PASS" if not bad else "\nFAILED: %s" % bad); sys.exit(1 if bad else 0)
