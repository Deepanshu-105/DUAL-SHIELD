#!/usr/bin/env python3
"""Dashboard security tests, part 2 (v13.4): 2-step sign-in (TOTP), operator role, plain-HTTP refusal, nonce CSP, audit mirror.
Run:  cd dashboard && npm run build && python3 test_security2.py"""
import base64, hashlib, hmac, http.client, json, os, struct, subprocess, sys, tempfile, time
PORT = 3078
tmp = tempfile.mkdtemp()
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
env = dict(os.environ, DASH_PASS="adminpass123", DASH_OPERATOR_PASS="operatorpass1", DASH_VIEW_PASS="viewerpass123", DASH_TOTP_SECRET=SECRET,
           DASH_AUDIT=tmp + "/audit.jsonl", DASH_AUDIT_MIRROR=tmp + "/mirror/audit.jsonl", DASH_REVOKED=tmp + "/rev.txt", GATEWAY_PORT="1")
srv = subprocess.Popen(["npx", "next", "start", "-p", str(PORT)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=os.path.dirname(os.path.abspath(__file__)))
ok = True
def totp(step):
    key = base64.b32decode(SECRET); h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest(); o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10**6)
def req(method, path, body=None, cookie=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    h = {"content-type": "application/json"}; h.update(headers or {})
    if cookie: h["cookie"] = cookie
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse(); data = r.read().decode(); return r.status, {k.lower(): v for k, v in r.getheaders()}, data
def check(name, cond):
    global ok; print(("PASS " if cond else "FAIL ") + name); ok &= bool(cond)
C = {"x-ds-confirm": "1"}
def login(pw, code="", headers=None):
    s, h, d = req("POST", "/api/auth/login", {"password": pw, "code": code}, headers=dict(C, **(headers or {})))
    return s, (h["set-cookie"].split(";")[0] if "set-cookie" in h else None), d
try:
    for _ in range(60):
        try: req("GET", "/login"); break
        except Exception: time.sleep(0.5)
    cur = int(time.time() // 30)
    check("admin password alone is refused when 2-step is on", login("adminpass123")[0] == 401)
    check("admin password + wrong code refused", login("adminpass123", "000000")[0] == 401)
    s, ck_admin, _ = login("adminpass123", totp(cur - 1))
    check("admin password + right code works", s == 200 and ck_admin)
    check("the same code cannot be used twice (replay)", login("adminpass123", totp(cur - 1))[0] == 401)
    s, ck_op, _ = login("operatorpass1", totp(cur))
    check("operator login works with a fresh code", s == 200 and ck_op)
    s, ck_view, _ = login("viewerpass123")
    check("viewer needs no code", s == 200 and ck_view)
    check("operator may run a Layer 2 action (reaches the route, not blocked)", req("POST", "/api/rollback", {}, ck_op, C)[0] != 403)
    check("operator may NOT use governance", req("POST", "/api/admin/chain", {"action": "propose"}, ck_op, C)[0] == 403)
    check("operator may NOT read the audit log", req("GET", "/api/audit", cookie=ck_op)[0] == 403)
    check("admin may read the audit log", req("GET", "/api/audit", cookie=ck_admin)[0] == 200)
    check("viewer still read-only", req("POST", "/api/rollback", {}, ck_view, C)[0] == 403)
    s, h, _ = req("GET", "/login", cookie=None)
    csp = h.get("content-security-policy", "")
    script = [d for d in csp.split(";") if d.strip().startswith("script-src")][0]
    check("script policy uses a nonce and no 'unsafe-inline'", "'nonce-" in script and "'unsafe-inline'" not in script)
    s2, h2, _ = req("GET", "/login")
    check("a different nonce for every response", h2.get("content-security-policy") != csp)
    s, h, body = req("GET", "/login")
    nonce = h.get("content-security-policy", "").split("'nonce-")[1].split("'")[0]     # nonce of THIS response
    import re
    tags = re.findall(r"<script[^>]*>", body)
    check("EVERY script tag on the login page carries this response's nonce", len(tags) >= 5 and all(("nonce=\"" + nonce + "\"") in t for t in tags))
    s, h, d = login("adminpass123", totp(cur + 1), headers={"Host": "192.168.1.50:3000"})
    check("sign-in over plain HTTP from a remote host is refused (426)", s == 426)
    s, h, d = login("adminpass123", totp(cur + 1), headers={"Host": "192.168.1.50:3443", "X-Forwarded-Proto": "https"})
    check("same request through an https front is allowed", s == 200)
    time.sleep(0.5)
    a = open(tmp + "/audit.jsonl").read().strip().split("\n"); m = open(tmp + "/mirror/audit.jsonl").read().strip().split("\n")
    check("every audit line is mirrored to the second file", a == m and len(a) >= 8)
finally:
    srv.terminate()
print("ALL PASS" if ok else "SOME FAILED"); sys.exit(0 if ok else 1)
