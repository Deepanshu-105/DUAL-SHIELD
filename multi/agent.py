#!/usr/bin/env python3
"""Dual-Shield agent for four-laptop mode (standard library only; run as root).

Runs on the target laptop (ROLE=target) and the peer laptop (ROLE=peer) so the dashboard laptop
can read their state. Every request needs the header  X-Token: <AGENT_TOKEN>.

  GET  /ipset                 -> {"ips": [...]}          members of the ipset city_blacklist
  GET  /log?name=X&n=N        -> {"lines": [...]}        last N lines of a known log file
  POST /rollback  {"ip":..}   -> target only: restore data/sample_copy after the on-chain check
  POST /ransomware            -> target only: arm the watcher (kill rule) and start the mock attack
  GET  /health                -> {"ok": true, "role": ...}
Lab use only: do not expose this to a real network.
"""
import json, os, re, subprocess, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.environ.get("SHIELD_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
ROLE = os.environ.get("ROLE", "target")
TOKEN = os.environ.get("AGENT_TOKEN", "dualshield")
PORT = int(os.environ.get("AGENT_PORT", "8800"))
PY = os.environ.get("SHIELD_PY", sys.executable)
RDIR = os.path.join(ROOT, "ransomware")
LOGS = {
    "parser_block": "/var/log/parser_block.log",
    "peer_block": "/var/log/peer_block.log",
    "metrics": "/var/log/metrics.log",
    "watch": os.path.join(RDIR, "evidence", "watch.log"),
}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
watcher = None   # subprocess of detect.py watch


def tail(path, n):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().splitlines()[-n:]
    except OSError:
        return []


def ipset_members():
    try:
        out = subprocess.run(["ipset", "list", "city_blacklist"], capture_output=True, text=True)
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return [l.split()[0] for l in out.stdout.splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+", l)]


def run_rollback(ip):
    env = dict(os.environ)
    t0 = time.time()
    r = subprocess.run([PY, "rollback.py", "restore", "data/sample_copy", "--anchor", ip],
                       cwd=RDIR, env=env, capture_output=True, text=True, timeout=60)
    return {"ok": r.returncode == 0, "ms": int((time.time() - t0) * 1000), "output": r.stdout + r.stderr}


def start_ransomware():
    """Same steps as demo.sh stages 'kill rule armed' and 'attack', without Docker."""
    global watcher
    if watcher and watcher.poll() is None:
        watcher.terminate()
    open(os.path.join(RDIR, "evidence", "watch.log"), "w").close()
    subprocess.run([PY, "rollback.py", "snapshot", "data/sample"], cwd=RDIR, capture_output=True)
    wl = open(os.path.join(RDIR, "evidence", "watch.log"), "a")
    watcher = subprocess.Popen([PY, "-u", "detect.py", "watch", "data/sample_copy", "--kill"],
                               cwd=RDIR, stdout=wl, stderr=subprocess.STDOUT)
    time.sleep(2)
    subprocess.Popen([PY, "mock_crypto.py", "--delay", "0.5"], cwd=RDIR,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "output": "watcher armed, mock ransomware started"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        if self.headers.get("X-Token") != TOKEN:
            self.send(401, {"error": "bad token"})
            return False
        return True

    def do_GET(self):
        if not self.authed():
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            return self.send(200, {"ok": True, "role": ROLE})
        if u.path == "/ipset":
            ips = ipset_members()
            return self.send(200 if ips is not None else 500, {"ips": ips})
        if u.path == "/log":
            name = (q.get("name") or [""])[0]
            n = max(1, min(int((q.get("n") or ["50"])[0]), 1000))
            if name not in LOGS:
                return self.send(404, {"error": "unknown log"})
            return self.send(200, {"lines": tail(LOGS[name], n)})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if not self.authed():
            return
        body = {}
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        except ValueError:
            pass
        if ROLE != "target":
            return self.send(404, {"error": "target only"})
        if self.path == "/rollback":
            ip = body.get("ip", "")
            if not IP_RE.match(ip):
                return self.send(400, {"ok": False, "output": "bad ip"})
            return self.send(200, run_rollback(ip))
        if self.path == "/ransomware":
            return self.send(200, start_ransomware())
        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    print("agent role=%s port=%d root=%s" % (ROLE, PORT, ROOT), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
