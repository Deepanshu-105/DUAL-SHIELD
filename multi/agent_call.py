#!/usr/bin/env python3
"""Signed call to a Dual-Shield agent from a shell (stdlib only).
   multi/agent_call.py T|P METHOD /path [json-body]     secrets and addresses come from multi/config.env
Verifies the signed answer and prints the JSON. Exit 0 if the answer was authentic, 2 if not, 1 if unreachable."""
import hashlib, hmac, json, os, secrets, sys, time, urllib.request, urllib.error

def cfg():
    d = {}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.env")
    for line in open(path):
        line = line.split("#")[0].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d

def sig(secret, *parts):
    return hmac.new(secret.encode(), "\n".join(parts).encode(), hashlib.sha256).hexdigest()

def main():
    who, method, path = sys.argv[1], sys.argv[2], sys.argv[3]
    body = (sys.argv[4] if len(sys.argv) > 4 else "").encode()
    c = cfg()
    secret = c.get("AGENT_SECRET_" + who, "")
    if len(secret) < 16:
        sys.exit("AGENT_SECRET_%s not set in multi/config.env" % who)
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    req = urllib.request.Request("http://%s:%s%s" % (c[who + "_IP"], os.environ.get("AGENT_PORT", "8800"), path), data=body or None, method=method, headers={
        "X-Ts": ts, "X-Nonce": nonce, "X-Sig": sig(secret, method, path, ts, nonce, hashlib.sha256(body).hexdigest()),
        "content-type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=int(os.environ.get("AGENT_CALL_TIMEOUT", "5")))
        code, raw, hdr = r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        code, raw, hdr = e.code, e.read(), e.headers
    except OSError as e:
        print("unreachable: %s" % e); sys.exit(1)
    want = sig(secret, nonce, str(code), hashlib.sha256(raw).hexdigest())
    if not hmac.compare_digest(want, hdr.get("X-Resp-Sig", "")):
        print("ANSWER NOT AUTHENTIC (status %d)" % code); sys.exit(2)
    print(raw.decode())

main()
