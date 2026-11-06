#!/usr/bin/env python3
"""Peer registry for laptop D (stdlib only). Peers find each other through D, so only D's address is configured.

  python3 multi/registry.py                 # serve on :8801 (REGISTRY_PORT); secrets from the environment
  python3 multi/registry.py --show          # print the current table

Protocol (all signed with the role's own secret, the same AGENT_SECRET_T / AGENT_SECRET_P the agents use):
  POST /register   {"role","name","ts","nonce","sig"}          sig = HMAC(secret, "register\nrole\nname\nts\nnonce")
  GET  /peers      headers X-Role, X-Ts, X-Nonce, X-Sig        sig = HMAC(secret, "peers\nrole\nts\nnonce")
  every answer carries X-Resp-Sig = HMAC(secret, nonce\ncode\nsha256(body)), so a man in the middle cannot forge it.
The address that is stored is the TCP source address of the request, never a value the sender claims.
Safeguards: stale or replayed requests refused; unknown role or bad signature refused; a role that is still online
cannot be taken over from another address (409) until its heartbeat has expired (a stolen key cannot hijack a live
node); per-source rate limit; the table is only shown to authenticated peers.
Registering does NOT make a laptop a chain node. Trust is still decided by the contract (addNode / approved nodes).
"""
import hashlib, hmac, ipaddress, json, os, re, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PEERS = os.environ.get("PEERS_FILE", os.path.join(HERE, "peers.json"))
ROLES = {"target": "AGENT_SECRET_T", "peer": "AGENT_SECRET_P"}
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{0,32}$")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sign(secret, *parts):
    return hmac.new(secret.encode(), "\n".join(parts).encode(), hashlib.sha256).hexdigest()


class Registry:
    def __init__(self, secrets, path=PEERS, skew=60, ttl=120, rate=30, clock=time.time, log=print):
        self.secrets, self.path, self.skew, self.ttl, self.rate = secrets, path, skew, ttl, rate
        self.clock, self.log = clock, log
        self.seen, self.hits, self.lock = {}, {}, threading.Lock()
        self.table = {}
        try:
            self.table = json.load(open(path)).get("peers", {})
        except (OSError, ValueError):
            pass

    # ---- helpers
    def _fresh(self, ts):
        try:
            return abs(self.clock() - int(ts)) <= self.skew
        except (TypeError, ValueError):
            return False

    def _limited(self, src):
        now = self.clock()
        h = [t for t in self.hits.get(src, []) if now - t < 60]
        h.append(now)
        self.hits[src] = h
        return len(h) > self.rate

    def _replay(self, nonce):
        now = self.clock()
        for k in [k for k, v in self.seen.items() if v < now]:
            del self.seen[k]
        if nonce in self.seen:
            return True
        self.seen[nonce] = now + 2 * self.skew
        return False

    def _save(self):
        tmp = self.path + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump({"t": self.clock(), "ttl": self.ttl, "peers": self.table}, f, indent=1)
        os.replace(tmp, self.path)

    def _gate(self, role, ts, nonce, sig, src, msg):
        """-> (code, error) or (None, secret)"""
        secret = self.secrets.get(role, "")
        if self._limited(src):
            return 429, "rate limit"
        if role not in ROLES or len(secret) < 16:
            return 403, "unknown role"
        if not self._fresh(ts):
            return 401, "stale request"
        if not nonce or not hmac.compare_digest(sign(secret, *msg), sig or ""):
            return 401, "bad signature"
        if self._replay(nonce):
            return 401, "replayed request"
        return None, secret

    # ---- operations (return (code, object, secret-for-response-signing or None))
    def register(self, role, src, name, ts, nonce, sig):
        with self.lock:
            name = name or ""
            if not NAME_RE.match(name):
                return 400, {"error": "bad name"}, None
            try:
                ipaddress.ip_address(src)
            except ValueError:
                return 400, {"error": "bad source address"}, None
            code, res = self._gate(role, ts, nonce, sig, src, ["register", str(role), name, str(ts), str(nonce)])
            if code:
                self.log("REGISTRY_REJECT %s from %s: %s" % (role, src, res))
                return code, {"error": res}, None
            now = self.clock()
            old = self.table.get(role)
            if old and old["ip"] != src and now - old["last"] <= self.ttl:
                self.log("REGISTRY_CONFLICT %s: %s is online, %s refused" % (role, old["ip"], src))
                return 409, {"error": "role already online at another address"}, res
            if not old or old["ip"] != src:
                self.log("REGISTRY_JOIN %s %s%s" % (role, src, (" (was %s)" % old["ip"]) if old else ""))
            self.table[role] = {"ip": src, "name": name, "first": old["first"] if old and old["ip"] == src else now, "last": now}
            self._save()
            return 200, {"ok": True, "ip": src, "ttl": self.ttl}, res

    def peers(self, role, src, ts, nonce, sig):
        with self.lock:
            code, res = self._gate(role, ts, nonce, sig, src, ["peers", str(role), str(ts), str(nonce)])
            if code:
                self.log("REGISTRY_REJECT peers %s from %s: %s" % (role, src, res))
                return code, {"error": res}, None
            now = self.clock()
            out = {r: {"ip": v["ip"], "name": v.get("name", ""), "age": int(now - v["last"]), "online": now - v["last"] <= self.ttl}
                   for r, v in self.table.items()}
            return 200, {"peers": out, "ttl": self.ttl}, res


class H(BaseHTTPRequestHandler):
    reg = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, secret, nonce):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        if secret and nonce:
            self.send_header("X-Resp-Sig", sign(secret, nonce, str(code), sha(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        try:
            raw = self.rfile.read(min(int(self.headers.get("content-length") or 0), 4096))
            d = json.loads(raw or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad body"}, None, None)
        if self.path != "/register":
            return self._send(404, {"error": "not found"}, None, None)
        code, obj, secret = self.reg.register(d.get("role"), self.client_address[0], d.get("name", ""), d.get("ts"), d.get("nonce"), d.get("sig"))
        self._send(code, obj, secret, d.get("nonce"))

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True}, None, None)
        if self.path != "/peers":
            return self._send(404, {"error": "not found"}, None, None)
        h = self.headers
        code, obj, secret = self.reg.peers(h.get("X-Role"), self.client_address[0], h.get("X-Ts"), h.get("X-Nonce"), h.get("X-Sig"))
        self._send(code, obj, secret, h.get("X-Nonce"))


def secrets_from_env():
    return {role: os.environ.get(var, "") for role, var in ROLES.items()}


def main():
    if "--show" in sys.argv:
        try:
            print(json.dumps(json.load(open(PEERS)), indent=1))
        except (OSError, ValueError):
            print("{}")
        return
    secrets = secrets_from_env()
    if not any(len(v) >= 16 for v in secrets.values()):
        sys.exit("AGENT_SECRET_T / AGENT_SECRET_P missing (run multi/gen_secrets.sh)")
    H.reg = Registry(secrets, ttl=int(os.environ.get("REGISTRY_TTL", "120")), log=lambda m: print(m, flush=True))
    port = int(os.environ.get("REGISTRY_PORT", "8801"))
    print("registry on :%d (peers file %s)" % (port, PEERS), flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    main()
