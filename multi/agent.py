#!/usr/bin/env python3
"""Dual-Shield agent for four-laptop mode (standard library only; run as root).

Runs on the target laptop (ROLE=target) and the peer laptop (ROLE=peer) so the dashboard laptop
can read their state. v2: every request is signed (HMAC-SHA256 over method, path, time, nonce and body
hash) with the secret AGENT_SECRET, and every answer is signed back. The secret never crosses the network.
Headers:  X-Ts (unix seconds), X-Nonce (random), X-Sig (hex).  Answer header: X-Resp-Sig.

  GET  /ipset                 -> {"ips": [...]}          members of the ipset city_blacklist
  GET  /log?name=X&n=N        -> {"lines": [...]}        last N lines of a known log file
  POST /rollback  {"ip":..}   -> target only: restore data/sample_copy after the on-chain check
  POST /ransomware            -> target only: arm the watcher (kill rule) and start the mock attack
  GET  /recovery              -> target only: vault, guard, containment and last recovery (JSON for the dashboard)
  POST /recover               -> target only: verified recovery from the vault into data/sample_copy (in place)
  POST /unfreeze              -> target only: unfreeze the vault and restart the guard
  GET  /health                -> {"ok": true, "role": ...}
Lab use only: do not expose this to a real network.
"""
import hashlib, hmac, json, os, re, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.environ.get("SHIELD_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
ROLE = os.environ.get("ROLE", "target")
SECRET = os.environ.get("AGENT_SECRET", "").encode()
SKEW = int(os.environ.get("AGENT_SKEW", "60"))      # seconds a signed request stays valid
SEEN = {}                                            # nonce -> expiry, to refuse replays
SEEN_LOCK = threading.Lock()
PORT = int(os.environ.get("AGENT_PORT", "8800"))
PY = os.environ.get("SHIELD_PY", sys.executable)
RDIR = os.path.join(ROOT, "ransomware")
LOGS = {
    "parser_block": "/var/log/parser_block.log",
    "peer_block": "/var/log/peer_block.log",
    "metrics": "/var/log/metrics.log",
    "flood": "/var/log/flood_block.log",
    "login": "/var/log/login_block.log",
    "arp": "/var/log/arp_alert.log",
    "sensor": "/var/log/sensor_alert.log",
    "watch": os.path.join(RDIR, "evidence", "watch.log"),
}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
watcher = None   # subprocess of detect.py watch
guard = None     # subprocess of guard.py (continuous vault + kill rule + containment)
USE_GUARD = os.environ.get("GUARD", "1") == "1"


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
    if USE_GUARD:
        if not start_guard(fresh=True):
            return {"ok": False, "output": "guard failed to start (see ransomware/evidence/watch.log)"}
        time.sleep(1)
        subprocess.Popen([PY, "mock_crypto.py", "--delay", "0.5"], cwd=RDIR,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": True, "output": "guard armed (vault + kill rule + containment), mock ransomware started"}
    wl = open(os.path.join(RDIR, "evidence", "watch.log"), "a")
    watcher = subprocess.Popen([PY, "-u", "detect.py", "watch", "data/sample_copy", "--kill"],
                               cwd=RDIR, stdout=wl, stderr=subprocess.STDOUT)
    time.sleep(2)
    subprocess.Popen([PY, "mock_crypto.py", "--delay", "0.5"], cwd=RDIR,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "output": "watcher armed, mock ransomware started"}


def vault_summary():
    r = subprocess.run([PY, "vault.py", "summary"], cwd=RDIR, capture_output=True, text=True, timeout=20)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {"available": False, "error": (r.stderr or r.stdout)[-200:]}


def stop_guard():
    global guard
    if guard and guard.poll() is None:
        guard.terminate()
        try:
            guard.wait(5)
        except subprocess.TimeoutExpired:
            guard.kill()
    guard = None


def start_guard(fresh=False):
    """guard.py = detect + kill rule + continuous gated vault + containment. Output goes to watch.log,
    which the dashboard and triage.py already read. fresh=True starts from a clean vault and folder (demo)."""
    global guard
    stop_guard()
    if fresh:
        subprocess.run("rm -rf data/vault data/vault.frozen data/vault.push.json evidence/containment.json "
                       "evidence/recovery_report.json evidence/guard.json", shell=True, cwd=RDIR)
        subprocess.run("rm -rf data/sample_copy && cp -r data/sample data/sample_copy", shell=True, cwd=RDIR)
    wl = open(os.path.join(RDIR, "evidence", "watch.log"), "a")
    guard = subprocess.Popen([PY, "-u", "guard.py", "protect.json"], cwd=RDIR, stdout=wl, stderr=subprocess.STDOUT)
    for _ in range(100):
        if "GUARD_ON" in "".join(tail(LOGS["watch"], 20)) or guard.poll() is not None:
            break
        time.sleep(0.1)
    return guard.poll() is None


def run_recover(anchor_ip=None):
    t0 = time.time()
    cmd = [PY, "recover.py", "sample", "data/sample_copy", "--in-place"]
    if anchor_ip:
        cmd += ["--anchor", anchor_ip]
    r = subprocess.run(cmd, cwd=RDIR, capture_output=True, text=True, timeout=120)
    return {"ok": r.returncode == 0, "ms": int((time.time() - t0) * 1000), "output": r.stdout + r.stderr}


def run_unfreeze():
    r = subprocess.run([PY, "vault.py", "unfreeze"], cwd=RDIR, capture_output=True, text=True)
    ok = start_guard() if USE_GUARD else True        # the old watch points at the moved folder: restart it
    return {"ok": ok, "output": r.stdout + ("guard restarted" if ok else "guard failed to start")}


def sign(*parts):
    return hmac.new(SECRET, "\n".join(parts).encode(), hashlib.sha256).hexdigest()


class H(BaseHTTPRequestHandler):
    nonce = ""
    def log_message(self, *a):
        pass

    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        if self.nonce:   # sign the answer so a man in the middle cannot forge it
            self.send_header("X-Resp-Sig", sign(self.nonce, str(code), hashlib.sha256(b).hexdigest()))
        self.end_headers()
        self.wfile.write(b)

    def read_body(self):
        try:
            return self.rfile.read(int(self.headers.get("content-length") or 0))
        except ValueError:
            return b""

    def authed(self, raw):
        ts, nonce, sig = self.headers.get("X-Ts", ""), self.headers.get("X-Nonce", ""), self.headers.get("X-Sig", "")
        try:
            fresh = abs(time.time() - int(ts)) <= SKEW
        except ValueError:
            fresh = False
        want = sign(self.command, self.path, ts, nonce, hashlib.sha256(raw).hexdigest()) if (ts and nonce) else ""
        if not (fresh and want and hmac.compare_digest(want, sig)):
            self.send(401, {"error": "bad signature or stale request"})
            return False
        now = time.time()
        with SEEN_LOCK:
            for k in [k for k, v in SEEN.items() if v < now]:
                del SEEN[k]
            if nonce in SEEN:
                self.send(401, {"error": "replayed request"})
                return False
            SEEN[nonce] = now + 2 * SKEW
        self.nonce = nonce
        return True

    def do_GET(self):
        if not self.authed(self.read_body()):
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
        if u.path == "/recovery":
            if ROLE != "target":
                return self.send(404, {"error": "target only"})
            return self.send(200, vault_summary())
        self.send(404, {"error": "not found"})

    def do_POST(self):
        raw = self.read_body()
        if not self.authed(raw):
            return
        body = {}
        try:
            body = json.loads(raw or b"{}")
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
        if self.path == "/recover":
            ip = body.get("ip", "")
            return self.send(200, run_recover(ip if IP_RE.match(ip) else None))
        if self.path == "/unfreeze":
            return self.send(200, run_unfreeze())
        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    if len(SECRET) < 16:
        sys.exit("AGENT_SECRET missing or shorter than 16 characters. Run multi/gen_secrets.sh and fill multi/config.env.")
    print("agent role=%s port=%d root=%s" % (ROLE, PORT, ROOT), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
