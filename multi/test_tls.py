#!/usr/bin/env python3
"""Mutual TLS tests with real certificates from multi/make_tls.sh: agent-style server, registry + join over TLS, tunnel."""
import json, os, shutil, socket, ssl, subprocess, sys, tempfile, threading, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import tlsutil, registry, join
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)
if not shutil.which("openssl"):
    print("SKIP: openssl not installed"); sys.exit(0)

tmp = tempfile.mkdtemp(); T = os.path.join(tmp, "tls")
env = dict(os.environ, TLS_DIR=T, D_IP="127.0.0.1", T_IP="", P_IP="")
cfg = os.path.join(HERE, "config.env"); had = os.path.exists(cfg)
if not had: open(cfg, "w").write("D_IP=127.0.0.1\nT_IP=\nP_IP=\nA_IP=127.0.0.9\nTLS=1\n")   # TLS=1 before any certificate exists must not block make_tls.sh
try:
    r = subprocess.run(["bash", os.path.join(HERE, "make_tls.sh")], env=env, capture_output=True, text=True)
finally:
    if not had: os.remove(cfg)
check("make_tls.sh issues CA + 3 role certificates", r.returncode == 0 and all(os.path.exists(os.path.join(T, x, "node.crt")) for x in ("dashboard", "target", "peer")), r.stdout + r.stderr)
check("private keys are mode 600", all(oct(os.stat(os.path.join(T, x, "node.key")).st_mode & 0o777) == "0o600" for x in ("dashboard", "target", "peer")))
check("CA key is not copied into role folders", not any(os.path.exists(os.path.join(T, x, "ca.key")) for x in ("dashboard", "target", "peer")))
D, TT, PP = (os.path.join(T, x) for x in ("dashboard", "target", "peer"))

# a rogue CA and certificate: must never be accepted
rogue = os.path.join(tmp, "rogue"); os.makedirs(rogue)
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", rogue + "/node.key", "-out", rogue + "/node.crt", "-days", "2", "-subj", "/CN=dualshield-dashboard"], capture_output=True)
shutil.copy(rogue + "/node.crt", rogue + "/ca.crt")

class Echo(BaseHTTPRequestHandler):
    allowed = {"dualshield-dashboard"}; ok = True
    def log_message(self, *a): pass
    def setup(self):
        self.ok = tlsutil.accept_handshake(self.request, self.allowed) is not None
        super().setup()
    def handle(self):
        if self.ok: super().handle()
    def do_GET(self):
        b = b'{"hello": "agent"}'
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
def serve(dirpath, handler=Echo):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    s.socket = tlsutil.server_context(dirpath).wrap_socket(s.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]

port = serve(TT)                                  # a "target" agent
def ask(port, d, cn="dualshield-target"):
    try:
        c, raw, _ = tlsutil.request("https://127.0.0.1:%d" % port, "GET", "/", expect_cn=cn, ctx=tlsutil.client_context(d))
        return c, raw
    except (OSError, ssl.SSLError) as e:
        return None, str(e)
c, raw = ask(port, D)
check("dashboard certificate is accepted by the target agent", c == 200 and b"agent" in raw, raw)
c, raw = ask(port, PP)
check("peer certificate is refused by the target agent (wrong role)", c is None, (c, raw))
c, raw = ask(port, rogue)
check("certificate from a rogue CA is refused", c is None, (c, raw))
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.load_verify_locations(os.path.join(D, "ca.crt"))
    c, raw, _ = tlsutil.request("https://127.0.0.1:%d" % port, "GET", "/", ctx=ctx)
    check("client without a certificate is refused", False, (c, raw))
except (OSError, ssl.SSLError):
    check("client without a certificate is refused", True)
c, raw = ask(port, D, cn="dualshield-peer")
check("server with the wrong role name is refused by the client", c is None, (c, raw))
try:
    ctx = ssl.create_default_context(); tlsutil.request("https://127.0.0.1:%d" % port, "GET", "/", ctx=ctx)
    check("public CAs do not vouch for our servers", False)
except (OSError, ssl.SSLError):
    check("public CAs do not vouch for our servers", True)
try:
    plain = socket.create_connection(("127.0.0.1", port), timeout=3); plain.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); plain.settimeout(3)
    got = plain.recv(100)
    check("plain HTTP gets no data from a TLS agent", b"agent" not in got)
except OSError:
    check("plain HTTP gets no data from a TLS agent", True)

# registry over TLS + join client
ST, SP = "T-secret-0123456789abcdef", "P-secret-0123456789abcdef"
reg = registry.Registry({"target": ST, "peer": SP}, path=os.path.join(tmp, "peers.json"), log=lambda m: None)
registry.H.reg = reg
os.environ["TLS"] = "1"; os.environ["TLS_DIR"] = D
srv = ThreadingHTTPServer(("127.0.0.1", 0), registry.H)
srv.socket = tlsutil.server_context(D).wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
threading.Thread(target=srv.serve_forever, daemon=True).start(); rport = srv.server_address[1]
def jn(role, secret, d):
    e = dict(os.environ, TLS="1", TLS_DIR=d, ROLE=role, AGENT_SECRET=secret, D_IP="127.0.0.1", REGISTRY_PORT=str(rport), PEERS_ENV=os.path.join(tmp, "peers.env"))
    return subprocess.run([sys.executable, os.path.join(HERE, "join.py"), "--once"], env=e, capture_output=True, text=True, timeout=30)
r = jn("target", ST, TT); check("join over mutual TLS works", r.returncode == 0 and "JOIN_OK" in r.stdout, r.stdout + r.stderr)
r = jn("target", ST, rogue); check("join with a rogue certificate fails", r.returncode == 1 and "JOIN_FAIL" in r.stdout, r.stdout)
# a peer certificate presented in the target role still needs the right HMAC secret, and CN must be target/peer
r = jn("peer", SP, PP); check("peer joins and sees the target", r.returncode == 0 and "T_IP=127.0.0.1" in r.stdout, r.stdout + r.stderr)

# tunnel: plain echo service <- TLS server proxy <- TLS client proxy <- plain client
import tls_proxy
echo = socket.socket(); echo.bind(("127.0.0.1", 0)); echo.listen(5); eport = echo.getsockname()[1]
def echo_loop():
    while True:
        c, _ = echo.accept()
        threading.Thread(target=lambda c=c: [c.sendall(d) for d in iter(lambda: c.recv(4096), b"")], daemon=True).start()
threading.Thread(target=echo_loop, daemon=True).start()
def free():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
sp, cp = free(), free()
def run_proxy(*args): return subprocess.Popen([sys.executable, os.path.join(HERE, "tls_proxy.py"), *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
p1 = run_proxy("server", "--listen", "127.0.0.1:%d" % sp, "--to", "127.0.0.1:%d" % eport, "--allow", "dualshield-target,dualshield-peer", "--tls-dir", D)
p2 = run_proxy("client", "--listen", "127.0.0.1:%d" % cp, "--to", "127.0.0.1:%d" % sp, "--expect", "dualshield-dashboard", "--tls-dir", TT)
time.sleep(1.5)
try:
    s = socket.create_connection(("127.0.0.1", cp), timeout=5); s.sendall(b"ping-through-tunnel"); s.settimeout(5)
    check("data flows through the TLS tunnel", s.recv(100) == b"ping-through-tunnel")
    s.close()
    # what an eavesdropper sees on the wire: capture bytes by connecting to the TLS side with a raw socket
    raw = socket.create_connection(("127.0.0.1", sp), timeout=5); raw.sendall(b"ping-through-tunnel"); raw.settimeout(2)
    try: got = raw.recv(100)
    except OSError: got = b""
    check("the TLS side of the tunnel does not answer plain traffic", b"ping-through-tunnel" not in got)
    p3 = run_proxy("client", "--listen", "127.0.0.1:%d" % free(), "--to", "127.0.0.1:%d" % sp, "--tls-dir", rogue)
    time.sleep(0.5); p3.terminate()
finally:
    p1.terminate(); p2.terminate()
shutil.rmtree(tmp, ignore_errors=True)
print("ALL PASS" if not bad else "SOME FAILED: %s" % bad); sys.exit(1 if bad else 0)
