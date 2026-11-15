#!/usr/bin/env python3
"""Dashboard security tests, part 3 (v13.5): flood protection of the console, no unsafe-inline for scripts or <style>.  Run after npm run build."""
import http.client, json, os, subprocess, sys, tempfile, time
PORT = 3080
tmp = tempfile.mkdtemp()
env = dict(os.environ, DASH_PASS="adminpass123", DASH_RATE_ANON="40", DASH_AUDIT=tmp + "/audit.jsonl", DASH_REVOKED=tmp + "/rev.txt", GATEWAY_PORT="1")
srv = subprocess.Popen(["npx", "next", "start", "-p", str(PORT)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=os.path.dirname(os.path.abspath(__file__)))
ok = True
def req(method, path, body=None, cookie=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    h = {"content-type": "application/json"}; h.update(headers or {})
    if cookie: h["cookie"] = cookie
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse(); data = r.read().decode(); return r.status, {k.lower(): v for k, v in r.getheaders()}, data
def check(name, cond):
    global ok; print(("PASS " if cond else "FAIL ") + name); ok &= bool(cond)
try:
    for _ in range(60):
        try: req("GET", "/login"); break
        except Exception: time.sleep(0.5)
    s, h, _ = req("POST", "/api/auth/login", {"password": "adminpass123"}, headers={"x-ds-confirm": "1"})
    ck = h["set-cookie"].split(";")[0]
    s, h, _ = req("GET", "/login")
    csp = h["content-security-policy"]
    style = [d for d in csp.split(";") if d.strip().startswith("style-src ")][0]
    check("<style> policy uses a nonce, no 'unsafe-inline' (only style attributes stay open)", "'nonce-" in style and "'unsafe-inline'" not in style and "style-src-attr 'unsafe-inline'" in csp)
    codes = [req("GET", "/api/peers")[0] for _ in range(80)]
    check("anonymous flood is refused with 429", 429 in codes)
    s, h, _ = req("GET", "/login")
    check("429 carries Retry-After", s == 429 and int(h.get("retry-after", "0")) > 0)
    check("a signed-in operator keeps working during the flood", req("GET", "/api/auth/me", cookie=ck)[0] == 200)
    time.sleep(0.5)
    a = [json.loads(l) for l in open(tmp + "/audit.jsonl").read().strip().split("\n")]
    check("the flood is audited once, not once per request", sum(1 for e in a if e["action"] == "RATE_LIMITED") == 1)
finally:
    srv.terminate()
print("ALL PASS" if ok else "SOME FAILED"); sys.exit(0 if ok else 1)
