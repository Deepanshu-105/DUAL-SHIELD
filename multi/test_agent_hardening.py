#!/usr/bin/env python3
"""v13.15: real agent on localhost: allow-list, lockout after bad signatures, body cap, slow client, demo endpoint off in PRODUCTION."""
import hashlib, hmac, http.client, json, os, socket, sys, threading, time
os.environ.update(AGENT_SECRET="s" * 24, ROLE="target", PRODUCTION="1", AGENT_FAIL_MAX="4", AGENT_MAX_BODY="1000", AGENT_IO_TIMEOUT="1", AGENT_BAN_SECS="300")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent
from http.server import ThreadingHTTPServer
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
srv = ThreadingHTTPServer(("127.0.0.1", 0), agent.H); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
def call(method, path, body=b"", sig=True):
    ts, nonce = str(int(time.time())), os.urandom(8).hex()
    h = {"X-Ts": ts, "X-Nonce": nonce, "X-Sig": agent.sign(method, path, ts, nonce, hashlib.sha256(body).hexdigest()) if sig else "00"}
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request(method, path, body=body, headers=h); r = c.getresponse(); return r.status, r.read()
    except (OSError, http.client.HTTPException) as e: return 0, str(e).encode()
check("good signed request works", call("GET", "/health")[0] == 200)
check("demo endpoint /ransomware refused in PRODUCTION", call("POST", "/ransomware", b"{}")[0] == 403)
check("oversized body = 413", call("POST", "/recover", b"x" * 5000)[0] == 413)
check("address allow-list", agent.ip_allowed("10.0.0.5", agent._nets("10.0.0.0/24")) and not agent.ip_allowed("10.0.1.5", agent._nets("10.0.0.0/24")) and agent.ip_allowed("1.2.3.4", []))
s = socket.create_connection(("127.0.0.1", port)); s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n"); t0 = time.time()
try: s.settimeout(5); d = s.recv(100)
except OSError: d = b""
check("slow client (never finishes its request) is cut after the timeout", time.time() - t0 < 4); s.close()
codes = [call("GET", "/health", sig=False)[0] for _ in range(4)]
check("bad signatures answer 401", codes[:3] == [401, 401, 401])
check("after 4 bad signatures the address is banned (even a good request is dropped)", agent.banned("127.0.0.1") and call("GET", "/health")[0] == 0)
check("ban expires", not agent.banned("127.0.0.1", now=time.time() + 400))
sys.exit(1 if bad else 0)
