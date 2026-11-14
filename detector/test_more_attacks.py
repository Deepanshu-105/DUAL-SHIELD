"""Tests for login_watch, arp_watch, sensor_guard and the canary/burst rules.  python3 detector/test_more_attacks.py
(the guard test needs root-free file access only; it works in a throw-away copy)"""
import json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "network"))
from login_watch import LoginAnalyzer, parse
from arp_watch import ArpAnalyzer, parse_neigh
from sensor_guard import SensorGuard, sign

ok_all = True


def check(name, cond, extra=""):
    global ok_all
    ok_all &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("  " + str(extra) if extra else ""))


def kinds(evs):
    return sorted({k for k, *_ in evs})


# ---- login_watch
check("log parser: fail / invalid / accepted",
      parse("sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2") == ("1.2.3.4", "root", False)
      and parse("sshd[1]: Invalid user bob from 5.6.7.8 port 1") == ("5.6.7.8", "bob", False)
      and parse("sshd[1]: Accepted publickey for amy from 9.9.9.9 port 22 ssh2") == ("9.9.9.9", "amy", True))
a = LoginAnalyzer()
ev = []
for i in range(12):                                         # one try every 40 s: invisible to a 3-in-5s rule
    ev += a.feed(1000 + i * 40, "198.51.100.5", "root", False)
check("slow brute force caught", kinds(ev) == ["slow-bruteforce"], kinds(ev))
a = LoginAnalyzer()
ev = []
for i, u in enumerate(["a", "b", "c", "d", "e", "f"]):
    ev += a.feed(1000 + i * 30, "198.51.100.6", u, False)
check("password spraying caught", "password-spray" in kinds(ev), kinds(ev))
a = LoginAnalyzer()
ev = []
for i in range(16):
    ev += a.feed(1000 + i * 20, "203.0.113.%d" % (i % 4 + 1), "admin", False)
check("distributed guessing caught on every source", len([e for e in ev if e[0] == "distributed-guess"]) == 4, kinds(ev))
a = LoginAnalyzer()
for i in range(4):
    a.feed(1000 + i * 10, "198.51.100.7", "amy", False)
check("successful login after failures flagged", kinds(a.feed(1050, "198.51.100.7", "amy", True)) == ["login-after-fails"])
a = LoginAnalyzer(allow_ips={"10.0.0.5"}, tor={"185.220.101.1"})
check("login from outside allow-list / Tor flagged",
      kinds(a.feed(1000, "185.220.101.1", "amy", True)) == ["login-from-tor", "login-unexpected"])
check("normal login from allowed IP is quiet", not LoginAnalyzer(allow_ips={"10.0.0.5"}).feed(1000, "10.0.0.5", "amy", True))
check("whitelisted source never flagged", not LoginAnalyzer(whitelist={"172.30.0.1"}).feed(1000, "172.30.0.1", "x", False))

# ---- arp_watch
GW, REAL, EVIL = "192.168.1.1", "aa:aa:aa:aa:aa:aa", "ee:ee:ee:ee:ee:ee"
t_ok = parse_neigh("192.168.1.1 dev eth0 lladdr aa:aa:aa:aa:aa:aa REACHABLE\n192.168.1.50 dev eth0 lladdr 11:11:11:11:11:11 STALE\n192.168.1.99 dev eth0  FAILED\n")
check("neighbour table parsed (FAILED skipped)", set(t_ok) == {GW, "192.168.1.50"})
an = ArpAnalyzer()
check("normal table is quiet", not an.feed(100, t_ok, GW))
t_bad = {GW: (EVIL, "eth0"), "192.168.1.50": ("11:11:11:11:11:11", "eth0"), "192.168.1.66": (EVIL, "eth0")}
ev = an.feed(110, t_bad, GW)
check("gateway MAC change caught, with the fix command", any(k == "gateway-mac-changed" and "nud permanent" in (x or "") for k, _, _, x in ev), kinds([(k,) for k, *_ in ev]))
check("spoofer IP identified (it shares the gateway's new MAC)", any(k == "mac-claims-many-ips" and ip == "192.168.1.66" for k, ip, _, _ in ev))

# ---- sensor_guard
def mk(i, t, v, seq, g="d1", secret=None, typ="temp_c"):
    r = {"id": "s%d" % i, "type": typ, "value": v, "ts": float(t), "seq": seq, "group": g}
    if secret:
        r["sig"] = sign(secret, r)
    return r

g = SensorGuard(secret="k")
for t in range(0, 20, 2):
    for i in range(1, 6):
        g.feed(mk(i, t, 25.0 + i * 0.1, t // 2 + 1, secret="k"))
check("normal readings are quiet", not g.flagged)
check("forged reading (bad signature)", kinds(g.feed(dict(mk(1, 30, 25.0, 99, secret="k"), sig="00"))) == ["forged-reading"])
check("replayed message", kinds(g.feed(mk(2, 40, 25.2, 3, secret="k"))) == ["replay"])
check("out-of-range value", "out-of-range" in kinds(g.feed(mk(3, 50, 200.0, 50, secret="k"))))
check("impossible jump", "impossible-jump" in kinds(g.feed(mk(4, 20, 45.0, 60, secret="k"))))
g3 = SensorGuard()
for i in range(1, 6):
    g3.feed(mk(i, 0, 25.0 + i * 0.1, 1))
for k in range(1, 7):                                      # drift 1.5 degrees every 2 s (0.75/s: each step legal)
    ev = g3.feed(mk(3, 2 * k, 25.3 + 1.5 * k, k + 1))
    for i in (1, 2, 4, 5):
        g3.feed(mk(i, 2 * k, 25.0 + i * 0.1, k + 1))
    if ev:
        break
check("slow drift caught by neighbour comparison", "neighbour-outlier" in kinds(ev), kinds(ev))
g4 = SensorGuard()
ev = []
for k in range(12):
    ev += g4.feed(mk(9, 2 * k, 21.0, k + 1, g=None))
check("stuck (frozen) sensor", "stuck-value" in kinds(ev), kinds(ev))
check("flagged sensor is quarantined locally", "s3" in g.quarantined)

# ---- guard: canary + burst, in a throw-away copy
tmp = tempfile.mkdtemp(prefix="dscan_")
work = os.path.join(tmp, "ransomware")
shutil.copytree(os.path.join(ROOT, "ransomware"), work, ignore=shutil.ignore_patterns("data", "evidence", "__pycache__", "baseline.json"))
os.makedirs(os.path.join(tmp, "multi"), exist_ok=True); shutil.copy(os.path.join(ROOT, "multi", "shield_os.py"), os.path.join(tmp, "multi"))   # v10: the OS layer sits next to ransomware/
os.chdir(work)
os.makedirs("data/docs")
for i in range(6):
    open("data/docs/f%d.txt" % i, "w").write(("line %d of file %d\n" % (i, i)) * 300)
json.dump({"roots": [{"name": "docs", "path": "data/docs"}], "debounce_s": 1, "kill": True, "contain": "dry",
           "canary": True, "burst_files": 5, "burst_window_s": 5}, open("protect.json", "w"))
log = open("g.log", "w")
gp = subprocess.Popen([sys.executable, "-u", "guard.py", "protect.json"], stdout=log, stderr=subprocess.STDOUT)
def wait(txt, secs):
    t = time.time()
    while time.time() - t < secs:
        if txt in open("g.log").read():
            return True
        time.sleep(0.1)
    return False
try:
    check("guard started with decoys", wait("GUARD_ON", 15) and os.path.exists("data/docs/.~ds_canary_a.docx"))
    # a slow attacker: keeps ONE file open and rewrites only a decoy, keeping every real file's header intact
    atk = subprocess.Popen([sys.executable, "-c",
        "import time; f=open('data/docs/f0.txt','a'); time.sleep(0.5); open('data/docs/.~ds_canary_a.docx','w').write('ENCRYPTED'); time.sleep(30)"])
    check("decoy touched -> CANARY_TOUCHED", wait("CANARY_TOUCHED", 10))
    check("single decoy is enough for KILL_TRIGGER", wait("KILL_TRIGGER", 5))
    check("attacker killed", wait("KILLED pid=", 5), "")
    check("vault frozen + contained", wait("CONTAINED", 5) and os.path.exists("data/vault.frozen"))
    atk.kill()
finally:
    gp.terminate(); gp.wait(5)
subprocess.run([sys.executable, "vault.py", "unfreeze"], capture_output=True)
os.remove("g.log"); os.system("rm -rf data/vault evidence")
log = open("g.log", "w")
gp = subprocess.Popen([sys.executable, "-u", "guard.py", "protect.json"], stdout=log, stderr=subprocess.STDOUT)
try:
    wait("GUARD_ON", 15)
    time.sleep(1.5)
    for i in range(6):                                      # six files change within 5 s: mass change
        open("data/docs/f%d.txt" % i, "a").write("edit\n")
        time.sleep(0.1)
    check("burst of 6 changes -> BURST + frozen", wait("BURST", 8) and wait("CONTAINED", 5))
finally:
    gp.terminate(); gp.wait(5)
shutil.rmtree(tmp, ignore_errors=True)
print("\nALL PASS" if ok_all else "\nSOME FAILED")
sys.exit(0 if ok_all else 1)
