#!/usr/bin/env python3
"""Host tamper watch for T and P.   python3 multi/node_watch.py --init | --once | --accept | (loop)

Takes a baseline of what a clean node looks like and then reports what changes: new listening ports, new uid-0 accounts, changed
authorized_keys / cron / systemd units / sudoers, /etc/ld.so.preload (a classic rootkit hook), new kernel modules, new setuid programs.
Findings are printed as NODEWATCH_ALERT lines, appended to /var/log/nodewatch.log (D can read it through the signed agent: log "nodewatch")
and each finding is reported once until you run --accept (after a change you made yourself).
If SELFGUARD_KEY is set the baseline is HMAC-signed, so editing the baseline file as well needs the key.
Honest limit: root can stop this process or rewrite everything; this makes quiet changes visible, it does not make a rooted host safe.
Env: NW_ROOT (test root, default /), NW_STATE, NW_LOG, NW_EVERY (30 s).
"""
import glob, hashlib, hmac, json, os, sys, time
ROOT = os.environ.get("NW_ROOT", "/")
STATE = os.environ.get("NW_STATE", "/var/lib/dualshield/nodewatch.baseline.json")
LOG = os.environ.get("NW_LOG", "/var/log/nodewatch.log")
EVERY = float(os.environ.get("NW_EVERY", "30"))
KEY = os.environ.get("SELFGUARD_KEY", "").encode()
SUID_DIRS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
def P(x): return os.path.join(ROOT, x.lstrip("/"))
def sha(path):
    try:
        with open(path, "rb") as f: return hashlib.sha256(f.read()).hexdigest()
    except OSError: return None
def hashes(patterns):
    out = {}
    for pat in patterns:
        for f in sorted(glob.glob(P(pat))):
            if os.path.isfile(f): out[f[len(ROOT.rstrip("/")):] or f] = sha(f)
    return out
def listeners():
    out = set()
    for name in ("net/tcp", "net/tcp6"):
        try: lines = open(P("/proc/" + name)).read().splitlines()[1:]
        except OSError: continue
        for ln in lines:
            f = ln.split()
            if len(f) > 3 and f[3] == "0A":            # LISTEN
                out.add("tcp:%d" % int(f[1].rsplit(":", 1)[1], 16))
    return sorted(out)
def passwd():
    users, uid0 = [], []
    try:
        for ln in open(P("/etc/passwd")):
            a = ln.strip().split(":")
            if len(a) >= 7:
                users.append("%s:%s:%s" % (a[0], a[2], a[6]))
                if a[2] == "0": uid0.append(a[0])
    except OSError: pass
    return sorted(users), sorted(uid0)
def modules():
    try: return sorted(l.split()[0] for l in open(P("/proc/modules")) if l.strip())
    except OSError: return []
def suid():
    out = []
    for d in SUID_DIRS:
        for dp, _, files in os.walk(P(d)):
            for fn in files:
                fp = os.path.join(dp, fn)
                try:
                    if os.lstat(fp).st_mode & 0o4000: out.append(fp[len(ROOT.rstrip("/")):] or fp)
                except OSError: pass
    return sorted(out)
def snap():
    users, uid0 = passwd()
    return {"listeners": listeners(), "users": users, "uid0": uid0, "modules": modules(), "suid": suid(),
            "keys": hashes(["/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"]),
            "cron": hashes(["/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*"]),
            "units": hashes(["/etc/systemd/system/*.service", "/etc/systemd/system/*.timer"]),
            "sudoers": hashes(["/etc/sudoers", "/etc/sudoers.d/*"]),
            "preload": hashes(["/etc/ld.so.preload"])}
def diff(base, now):
    a = []
    for k in now["uid0"]:
        if k not in base["uid0"]: a.append(("CRITICAL", "uid0:" + k, "new account with uid 0: %s" % k))
    for k in now["preload"]:
        if k not in base["preload"] or base["preload"][k] != now["preload"][k]: a.append(("CRITICAL", "preload", "/etc/ld.so.preload is present or changed (library injection / rootkit hook)"))
    for k in now["listeners"]:
        if k not in base["listeners"]: a.append(("HIGH", "listen:" + k, "new listening port %s" % k))
    for k in now["suid"]:
        if k not in base["suid"]: a.append(("HIGH", "suid:" + k, "new setuid program %s" % k))
    for cat, label in (("keys", "authorized_keys"), ("cron", "cron file"), ("units", "systemd unit"), ("sudoers", "sudoers")):
        for f, h in now[cat].items():
            if f not in base[cat]: a.append(("HIGH", cat + ":" + f, "new %s %s" % (label, f)))
            elif base[cat][f] != h: a.append(("HIGH", cat + ":" + f, "%s changed: %s" % (label, f)))
    for k in now["users"]:
        if k not in base["users"] and k.split(":")[0] not in [u.split(":")[0] for u in base["users"]]: a.append(("MEDIUM", "user:" + k, "new account %s" % k.split(":")[0]))
    for k in now["modules"]:
        if k not in base["modules"]: a.append(("MEDIUM", "mod:" + k, "new kernel module %s" % k))
    return a
def sign(obj):
    return hmac.new(KEY, json.dumps(obj, sort_keys=True).encode(), hashlib.sha256).hexdigest() if KEY else ""
def save_base(s):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f: json.dump({"snap": s, "sig": sign(s)}, f)
    os.replace(tmp, STATE)
def load_base():
    try: d = json.load(open(STATE))
    except (OSError, ValueError): return None, "no baseline (run --init on a clean node)"
    if KEY and not hmac.compare_digest(d.get("sig", ""), sign(d["snap"])): return None, "baseline signature does not match (file edited without the key)"
    return d["snap"], ""
def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg); print(line, flush=True)
    try:
        with open(LOG, "a") as f: f.write(line + "\n")
    except OSError: pass
class Watch:
    def __init__(self): self.seen = set()
    def once(self):
        base, err = load_base()
        if base is None:
            if "tampered" in err or "signature" in err:
                if "sig" not in self.seen: self.seen.add("sig"); log("NODEWATCH_ALERT CRITICAL %s" % err)
            return None
        out = []
        for sev, key, msg in diff(base, snap()):
            if key not in self.seen: self.seen.add(key); log("NODEWATCH_ALERT %s %s" % (sev, msg)); out.append((sev, msg))
        return out
if __name__ == "__main__":
    if "--init" in sys.argv or "--accept" in sys.argv:
        save_base(snap()); log("NODEWATCH baseline %s" % ("accepted (changes since the last baseline are now trusted)" if "--accept" in sys.argv else "created")); sys.exit(0)
    w = Watch()
    if "--once" in sys.argv:
        r = w.once()
        if r is None: print("no usable baseline:", load_base()[1]); sys.exit(2)
        print("NODEWATCH: %d finding(s)" % len(r)); sys.exit(1 if r else 0)
    if load_base()[0] is None and "no baseline" in load_base()[1]: save_base(snap()); log("NODEWATCH first start: baseline created (run on a clean node!)")
    log("NODEWATCH on (every %g s)" % EVERY)
    while True:
        try: w.once()
        except Exception as e: print("NODEWATCH error: %s" % e, flush=True)
        time.sleep(EVERY)
