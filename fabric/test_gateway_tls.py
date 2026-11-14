#!/usr/bin/env python3
"""Strict mutual-TLS mode of the Fabric gateway (start it with GATEWAY_TLS=1 GATEWAY_LAB=0 TLS_DIR=multi/tls/dashboard).
Needs certificates from multi/make_tls.sh and a running Fabric network.
   GATEWAY_URL=https://127.0.0.1:8600 python3 fabric/test_gateway_tls.py"""
import os, sys, ssl, urllib.request, json
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "network"))
TLSD = os.path.join(ROOT, "multi", "tls")
url = os.environ.get("GATEWAY_URL", "https://127.0.0.1:8600")
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)

def call(role, method, path, obj=None, cert=True):
    ctx = ssl.create_default_context(cafile=os.path.join(TLSD, "ca.crt"))
    ctx.check_hostname = False
    if cert and role:
        ctx.load_cert_chain(os.path.join(TLSD, role, "node.crt"), os.path.join(TLSD, role, "node.key"))
    req = urllib.request.Request(url + path, data=json.dumps(obj).encode() if obj is not None else None, method=method, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

IDN = {0: "Org1MSP:Admin@org1.example.com", 1: "Org1MSP:User1@org1.example.com", 2: "Org2MSP:User1@org2.example.com"}
try:
    code, _ = call("dashboard", "GET", "/health")
except Exception as e:
    print("SKIP: no TLS gateway at %s (%s)" % (url, e)); sys.exit(0)
check("dashboard certificate is accepted", code == 200)
try:
    call(None, "GET", "/health", cert=False); ok = False
except Exception:
    ok = True
check("a client without a certificate cannot even connect", ok)
code, o = call("target", "POST", "/query", {"who": 1, "fn": "whoami", "args": []})
check("target certificate may use the target identity", code == 200 and "User1@org1" in o.get("result", ""), (code, o))
code, o = call("target", "POST", "/query", {"who": 0, "fn": "params", "args": []})
check("target certificate may NOT use the owner identity", code == 403, (code, o))
code, o = call("target", "POST", "/tx", {"who": 2, "fn": "registerNode", "args": []})
check("target certificate may NOT act as the peer", code == 403, (code, o))
code, o = call("peer", "POST", "/query", {"who": 2, "fn": "whoami", "args": []})
check("peer certificate may use the peer identity", code == 200 and "User1@org2" in o.get("result", ""), (code, o))
code, o = call("peer", "POST", "/query", {"who": 1, "fn": "whoami", "args": []})
check("peer certificate may NOT act as the target", code == 403, (code, o))
code, o = call("dashboard", "POST", "/query", {"who": 0, "fn": "params", "args": []})
check("dashboard certificate may use the owner identity", code == 200 and json.loads(o["result"])["K"] == 2, (code, o))
code, o = call("dashboard", "POST", "/query", {"who": 1, "fn": "whoami", "args": []})
check("dashboard certificate may NOT impersonate a node", code == 403, (code, o))
code, o = call("dashboard", "POST", "/query", {"who": 0, "fn": "not a name!", "args": []})
check("malformed function names are refused", code == 400, (code, o))
print("\nALL PASS" if not bad else "\nFAILED: %s" % bad); sys.exit(1 if bad else 0)
