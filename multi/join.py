#!/usr/bin/env python3
"""Join the Dual-Shield network knowing only D's address (stdlib only). Run on T and P (start scripts do it).

  ROLE=target AGENT_SECRET=... D_IP=192.168.1.10 python3 multi/join.py            # register + refresh every 30 s
  ... python3 multi/join.py --once --wait 60                                       # resolve now (wait for peers), then exit

Registers this laptop with D (signed), fetches the peer table (answer signature verified), and writes
multi/peers.env with T_IP= / P_IP= for the online peers (the start scripts source it). Exit 0 when joined.
"""
import argparse, hashlib, hmac, json, os, secrets as rnd, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ENVFILE = os.environ.get("PEERS_ENV", os.path.join(HERE, "peers.env"))
KEYS = {"target": "T_IP", "peer": "P_IP"}


def sign(secret, *parts):
    return hmac.new(secret.encode(), "\n".join(parts).encode(), hashlib.sha256).hexdigest()


def call(base, secret, method, path, role, body=None, timeout=5):
    ts, nonce = str(int(time.time())), rnd.token_hex(16)
    headers, data = {"content-type": "application/json"}, None
    if method == "POST":
        data = json.dumps(dict(body, role=role, ts=ts, nonce=nonce, sig=sign(secret, "register", role, body.get("name", ""), ts, nonce))).encode()
    else:
        headers.update({"X-Role": role, "X-Ts": ts, "X-Nonce": nonce, "X-Sig": sign(secret, "peers", role, ts, nonce)})
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        code, raw, hdr = r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        code, raw, hdr = e.code, e.read(), e.headers
    want = sign(secret, nonce, str(code), hashlib.sha256(raw).hexdigest())
    if code in (200, 409) and not hmac.compare_digest(want, hdr.get("X-Resp-Sig", "")):
        raise ValueError("registry answer is not signed correctly (wrong server or man in the middle)")
    return code, json.loads(raw or b"{}")


def write_env(peers, path=ENVFILE):
    lines = ["# written by multi/join.py; do not edit"]
    for role, key in KEYS.items():
        p = peers.get(role)
        if p and p.get("online"):
            lines.append("%s=%s" % (key, p["ip"]))
    tmp = path + ".tmp"
    open(tmp, "w").write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    return lines[1:]


def once(base, secret, role, name):
    code, r = call(base, secret, "POST", "/register", role, {"name": name})
    if code != 200:
        return False, "register refused (%d): %s" % (code, r.get("error", ""))
    code, r = call(base, secret, "GET", "/peers", role)
    if code != 200:
        return False, "peers refused (%d): %s" % (code, r.get("error", ""))
    return True, write_env(r["peers"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--wait", type=int, default=0, help="with --once: keep trying up to N seconds until the other peer is online too")
    ap.add_argument("--every", type=int, default=30)
    a = ap.parse_args()
    role = os.environ.get("ROLE", "")
    secret = os.environ.get("AGENT_SECRET", "")
    d = os.environ.get("D_IP", "")
    if role not in KEYS or len(secret) < 16 or not d:
        sys.exit("need ROLE (target|peer), AGENT_SECRET and D_IP in the environment")
    base = "http://%s:%s" % (d, os.environ.get("REGISTRY_PORT", "8801"))
    name = os.environ.get("NODE_NAME", "")
    other = "P_IP" if role == "target" else "T_IP"
    t0 = time.time()
    while True:
        try:
            ok, res = once(base, secret, role, name)
        except (OSError, ValueError) as e:
            ok, res = False, str(e)
        if ok:
            print("JOIN_OK %s" % " ".join(res), flush=True)
        else:
            print("JOIN_FAIL %s" % res, flush=True)
        if a.once:
            if ok and (any(x.startswith(other + "=") for x in res) or time.time() - t0 >= a.wait):
                return
            if time.time() - t0 >= a.wait:
                sys.exit(0 if ok else 1)
            time.sleep(2)
        else:
            time.sleep(a.every)


if __name__ == "__main__":
    main()
