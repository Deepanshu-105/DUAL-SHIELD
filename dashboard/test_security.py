#!/usr/bin/env python3
"""Dashboard security tests: starts the production server on a spare port with test passwords and attacks it.
Run:  cd dashboard && npm run build && python3 test_security.py"""
import http.client, json, os, subprocess, sys, tempfile, time, base64
PORT = 3077
tmp = tempfile.mkdtemp()
env = dict(os.environ, DASH_PASS="adminpass123", DASH_VIEW_PASS="viewerpass123", DASH_AUDIT=tmp + "/audit.jsonl", DASH_REVOKED=tmp + "/rev.txt", GATEWAY_PORT="1")
srv = subprocess.Popen(["npx", "next", "start", "-p", str(PORT)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=os.path.dirname(os.path.abspath(__file__)))
ok = True
def req(method, path, body=None, cookie=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    h = {"content-type": "application/json"}; h.update(headers or {})
    if cookie: h["cookie"] = cookie
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse(); data = r.read().decode(); return r.status, dict(r.getheaders()), data
def check(name, cond):
    global ok; print(("PASS " if cond else "FAIL ") + name); ok &= bool(cond)
def login(pw):
    s, h, d = req("POST", "/api/auth/login", {"password": pw}, headers={"x-ds-confirm": "1"})
    ck = [v for k, v in h.items() if k.lower() == "set-cookie"]
    return s, (ck[0].split(";")[0] if ck else None), ck[0] if ck else ""
C = {"x-ds-confirm": "1"}
try:
    for _ in range(60):
        try: req("GET", "/login"); break
        except Exception: time.sleep(0.5)
    check("page without session redirects to /login", req("GET", "/")[0] in (307, 308, 302))
    check("API without session is 401", req("GET", "/api/chain")[0] == 401)
    s, ck_admin, raw = login("adminpass123")
    check("admin login works, cookie is HttpOnly + SameSite=Strict", s == 200 and "HttpOnly" in raw and "SameSite=Strict" in raw)
    s, ck_view, _ = login("viewerpass123")
    check("viewer login works", s == 200)
    check("viewer may read", req("GET", "/api/peers", cookie=ck_view)[0] == 200)
    check("viewer may not POST", req("POST", "/api/rollback", {}, ck_view, C)[0] == 403)
    check("viewer may not read audit log", req("GET", "/api/audit", cookie=ck_view)[0] == 403)
    check("admin POST without confirm header refused", req("POST", "/api/rollback", {}, ck_admin)[0] == 403)
    check("admin POST marked cross-site refused", req("POST", "/api/rollback", {}, ck_admin, dict(C, **{"Sec-Fetch-Site": "cross-site"}))[0] == 403)
    check("governance input injection refused", req("POST", "/api/admin/chain", {"action": "propose", "kind": "2", "ip": "1.2.3.4; rm -rf /"}, ck_admin, C)[0] == 400)
    body, sig = ck_view.split("=", 1)[1].split(".")
    forged = base64.urlsafe_b64encode(base64.urlsafe_b64decode(body + "==").replace(b"viewer", b"admin")).decode().rstrip("=")
    check("forged role in cookie rejected", req("GET", "/api/peers", cookie="ds_session=%s.%s" % (forged, sig))[0] == 401)
    check("tampered signature rejected", req("GET", "/api/peers", cookie="ds_session=%s.%s" % (body, sig[::-1]))[0] == 401)
    s, h, _ = req("GET", "/api/auth/me", cookie=ck_admin)
    low = {k.lower(): v for k, v in h.items()}
    check("security headers present", "frame-ancestors 'none'" in low.get("content-security-policy", "") and low.get("x-frame-options") == "DENY" and low.get("x-content-type-options") == "nosniff")
    check("API responses are not cacheable", low.get("cache-control") == "no-store")
    req("POST", "/api/auth/logout", {}, ck_view, C)
    check("old cookie dead after logout", req("GET", "/api/peers", cookie=ck_view)[0] == 401)
    check("wrong password refused", login("wrongwrong")[0] == 401)
    codes = [login("badbadbad")[0] for _ in range(6)]
    check("lockout after repeated failures", 429 in codes)
    check("right password refused while locked", login("adminpass123")[0] == 429)
    audit = open(tmp + "/audit.jsonl").read().strip().split("\n")
    check("audit log written and hash-chained", len(audit) >= 5 and json.loads(audit[1])["prev"] == json.loads(audit[0])["h"])
finally:
    srv.terminate()
print("ALL PASS" if ok else "SOME FAILED"); sys.exit(0 if ok else 1)
