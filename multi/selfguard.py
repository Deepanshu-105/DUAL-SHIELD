#!/usr/bin/env python3
"""Who guards the guards? Tamper and outage watch for the defenders themselves.

  python3 multi/selfguard.py --init                  # record a signed manifest of the defender code (SHA-256 per file)
  python3 multi/selfguard.py --check                 # one check, exit 0 ok / 1 problem
  python3 multi/selfguard.py                         # loop every 10 s; writes ransomware/evidence/selfguard.json
  python3 multi/selfguard.py --watch "guard=guard.py::python3 guard.py protect.json" --restart --freeze-on-tamper

Checks: (1) every defender file still matches the manifest (HMAC-signed with SELFGUARD_KEY when set, so editing the
manifest as well needs the key); (2) files added or removed; (3) every --watch process pattern is running, and is
restarted with --restart; (4) the guard's heartbeat (evidence/guard.json) is fresh. Findings are printed as
SELFGUARD_TAMPER / SELFGUARD_DOWN / SELFGUARD_RESTARTED lines and shown on the dashboard.
Honest limit: an attacker with root can stop selfguard itself or rewrite everything including the key. This raises the
bar (and makes quiet tampering visible); run it as a systemd service (multi/install_services.sh) and keep the key off T.
"""
import argparse, glob, hashlib, hmac, json, os, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
MANIFEST = os.path.join(ROOT, "ransomware", "evidence", "selfguard.manifest.json")
STATUS = os.path.join(ROOT, "ransomware", "evidence", "selfguard.json")
GLOBS = ["detector/*.py", "network/*.py", "ransomware/*.py", "multi/*.py", "multi/*.sh", "blockchain/contracts/*.sol"]


def files():
    out = []
    for g in GLOBS:
        out += glob.glob(os.path.join(ROOT, g))
    return sorted(set(out))


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def snapshot():
    return {os.path.relpath(p, ROOT): sha(p) for p in files()}


def sign(files_map, key):
    body = json.dumps(files_map, sort_keys=True).encode()
    return hmac.new((key or "").encode(), body, hashlib.sha256).hexdigest()


def init():
    key = os.environ.get("SELFGUARD_KEY", "")
    m = snapshot()
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    json.dump({"t": time.time(), "files": m, "sig": sign(m, key), "signed": bool(key)}, open(MANIFEST, "w"), indent=1)
    print("SELFGUARD_INIT %d files, %s" % (len(m), "signed" if key else "UNSIGNED (set SELFGUARD_KEY for a signed manifest)"))


def verify_manifest():
    """-> (tampered files, added, removed, manifest_ok)"""
    if not os.path.exists(MANIFEST):
        return [], [], [], None
    man = json.load(open(MANIFEST))
    key = os.environ.get("SELFGUARD_KEY", "")
    sig_ok = hmac.compare_digest(man.get("sig", ""), sign(man["files"], key))
    now = snapshot()
    base = man["files"]
    changed = sorted(f for f in base if f in now and now[f] != base[f])
    removed = sorted(f for f in base if f not in now)
    added = sorted(f for f in now if f not in base)
    return changed, added, removed, sig_ok


def running(pattern):
    r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    me = str(os.getpid())
    return [p for p in r.stdout.split() if p != me]


def check(watch, restart, freeze, heartbeat_max=15):
    changed, added, removed, sig_ok = verify_manifest()
    st = {"t": time.time(), "manifest": "missing" if sig_ok is None else ("ok" if sig_ok else "SIGNATURE_BAD"),
          "tampered": changed, "added": added, "removed": removed, "down": [], "restarted": [], "heartbeat_stale": False}
    for name, (pat, cmd) in watch.items():
        if not running(pat):
            st["down"].append(name)
            print("SELFGUARD_DOWN %s" % name, flush=True)
            if restart and cmd and not (changed or removed or sig_ok is False):
                subprocess.Popen(cmd, shell=True, cwd=os.path.join(ROOT, "ransomware"), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                st["restarted"].append(name)
                print("SELFGUARD_RESTARTED %s" % name, flush=True)
    hb = os.path.join(ROOT, "ransomware", "evidence", "guard.json")
    if "guard" in watch and os.path.exists(hb):
        try:
            st["heartbeat_stale"] = time.time() - json.load(open(hb)).get("t", 0) > heartbeat_max and bool(running(watch["guard"][0]))
        except ValueError:
            pass
    for f in changed + removed:
        print("SELFGUARD_TAMPER %s" % f, flush=True)
    for f in added:
        print("SELFGUARD_NEW_FILE %s (planted code, or run --init after a deliberate update)" % f, flush=True)
    if sig_ok is False:
        print("SELFGUARD_TAMPER manifest signature does not match (manifest edited or wrong key)", flush=True)
    st["ok"] = not (changed or removed or added or st["down"] or st["heartbeat_stale"] or sig_ok is False)
    if freeze and (changed or removed or sig_ok is False):
        sys.path.insert(0, os.path.join(ROOT, "ransomware"))
        os.chdir(os.path.join(ROOT, "ransomware"))
        import vault
        vault.freeze("selfguard: defender code tampered")
    os.makedirs(os.path.dirname(STATUS), exist_ok=True)
    json.dump(st, open(STATUS, "w"))
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--watch", action="append", default=[], help='name=pgrep-pattern::restart command')
    ap.add_argument("--restart", action="store_true")
    ap.add_argument("--freeze-on-tamper", action="store_true")
    ap.add_argument("--every", type=float, default=10)
    a = ap.parse_args()
    if a.init:
        return init()
    watch = {}
    for w in a.watch:
        name, rest = w.split("=", 1)
        pat, _, cmd = rest.partition("::")
        watch[name] = (pat, cmd)
    if a.check:
        st = check(watch, a.restart, a.freeze_on_tamper)
        print(json.dumps(st))
        sys.exit(0 if st["ok"] else 1)
    print("SELFGUARD_ON watching %d files, %d processes" % (len(files()), len(watch)), flush=True)
    while True:
        check(watch, a.restart, a.freeze_on_tamper)
        time.sleep(a.every)


if __name__ == "__main__":
    main()
