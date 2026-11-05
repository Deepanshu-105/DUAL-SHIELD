#!/usr/bin/env python3
"""Measure Dual-Shield honestly: false alarms on normal behaviour, misses on attacks, and time to detect.

  python3 eval/run_eval.py            # prints tables, writes eval/REPORT.md and eval/results.json

Every detector's real analysis code is driven with simulated, seeded workloads (so results repeat). Simulated time
is used for network and login traffic; file checks use real files. This measures the DETECTION LOGIC, not the
operating system around it (packet capture limits, process attribution), and uses synthetic attackers, not real
malware. Read the numbers as "how the rules behave", not as a certification.
"""
import json, os, random, shutil, sys, tempfile, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ("detector", "network", "ransomware"):
    sys.path.insert(0, os.path.join(ROOT, d))
from flood_detector import FloodAnalyzer
from login_watch import LoginAnalyzer
from arp_watch import ArpAnalyzer
from sensor_guard import SensorGuard
import detect

R = {"benign": [], "attacks": []}


def benign(area, case, events, flagged, note=""):
    R["benign"].append({"area": area, "case": case, "events": events, "false_alarms": flagged, "note": note})


def attack(area, case, detected, latency=None, note=""):
    R["attacks"].append({"area": area, "case": case, "detected": bool(detected), "latency": latency, "note": note})


# ---------------------------------------------------------------- network floods / scans
def flood():
    rnd = random.Random(1)
    # benign 1: 300 ordinary clients, 0.5-6 new connections per second in bursts, 5 minutes
    a = FloodAnalyzer(); n = fl = 0
    for t10 in range(3000):
        t = t10 / 10
        for c in rnd.sample(range(300), 12):
            rate = rnd.choice([0.5, 1, 2, 3, 6])
            if rnd.random() < rate / 10:
                n += 1; fl += len(a.feed(t, "10.1.%d.%d" % (c // 250, c % 250 + 1), 443, "tcp", True))
    benign("network", "300 normal clients, 5 min", n, fl)
    # benign 2: a campus NAT: 40 users behind one address, ~60 new connections/s with page-load bursts
    a = FloodAnalyzer(); n = fl = 0
    for t100 in range(6000):
        t = t100 / 100
        k = 1 if rnd.random() < 0.6 else 0
        if int(t) % 20 == 0 and (t100 % 100) < 100:
            k = 2                                                  # burst: ~200/s for a second every 20 s
        for _ in range(k):
            n += 1; fl += len(a.feed(t, "100.64.0.9", 443, "tcp", True))
    benign("network", "shared NAT address, 60/s with bursts", n, fl, "false alarms here are real users blocked; use WHITELIST_CIDRS")
    # attacks
    def run(case, gen, want, area="network"):
        a = FloodAnalyzer(); first = None
        for t, ip, port, proto, syn in gen:
            ev = a.feed(t, ip, port, proto, syn)
            if any(k in want for k, _, _ in ev):
                first = t - 0.0 if first is None else first
                break
        attack(area, case, first is not None, None if first is None else round(first, 2))
    for pps in (50, 100, 200, 1000):
        run("SYN flood from one source, %d/s" % pps, ((i / pps, "198.51.100.9", 80, "tcp", True) for i in range(pps * 10)), {"syn-flood"})
    for pps in (5, 20, 100):
        run("port scan, %d ports/s" % pps, ((i / pps, "198.51.100.10", 1000 + i, "tcp", True) for i in range(pps * 10)), {"port-scan", "syn-flood"})
    run("slow port scan, 1 port/s", ((i, "198.51.100.11", 1000 + i, "tcp", True) for i in range(300)), {"port-scan"})
    run("UDP flood, 500/s", ((i / 500, "198.51.100.12", 53, "udp", False) for i in range(5000)), {"udp-flood"})
    for srcs, each in ((100, 8), (100, 3)):
        run("botnet, %d sources x %d/s (total %d/s)" % (srcs, each, srcs * each),
            ((i / (srcs * each), "203.0.113.%d" % (i % srcs + 1), 80, "tcp", True) for i in range(srcs * each * 10)), {"botnet"})


# ---------------------------------------------------------------- logins
def logins():
    rnd = random.Random(2)
    a = LoginAnalyzer(); n = fl = 0
    t = 1000.0
    for u in range(500):                                     # 500 users: most log in first time, some mistype
        ip = "10.2.%d.%d" % (u // 250, u % 250 + 1)
        typos = rnd.choices([0, 1, 2, 3], weights=[80, 12, 6, 2])[0]
        for _ in range(typos):
            n += 1; t += rnd.uniform(3, 20); fl += len(a.feed(t, ip, "user%d" % u, False))
        n += 1; t += rnd.uniform(3, 20); fl += len(a.feed(t, ip, "user%d" % u, True))
    benign("login", "500 users, some mistype (0-3 typos)", n, fl, "login-after-fails fires after >=4 failures (default); lower --after-fails to catch more, at the cost of flagging careless users")
    def run(case, evs, want):
        a = LoginAnalyzer(); first = None
        for i, (t, ip, user, ok) in enumerate(evs):
            ev = a.feed(t, ip, user, ok)
            if any(k in want for k, _, _ in ev):
                first = i + 1; break
        attack("login", case, first is not None, None if first is None else "after %d attempts" % first)
    run("slow brute force, 1 try / 60 s", [(1000 + i * 60, "198.51.100.5", "root", False) for i in range(60)], {"slow-bruteforce"})
    run("slow brute force, 1 try / 120 s", [(1000 + i * 120, "198.51.100.5", "root", False) for i in range(60)], {"slow-bruteforce"})
    run("password spraying, 6 users, 1 try each / 40 s", [(1000 + i * 40, "198.51.100.6", "u%d" % i, False) for i in range(6)], {"password-spray"})
    run("distributed guessing, 4 IPs, 1 try / 20 s", [(1000 + i * 20, "203.0.113.%d" % (i % 4 + 1), "admin", False) for i in range(40)], {"distributed-guess"})
    run("guessed password works (5 failures then success)", [(1000 + i * 10, "198.51.100.7", "amy", False) for i in range(5)] + [(1060, "198.51.100.7", "amy", True)], {"login-after-fails"})
    run("stolen password, first try, normal IP and hour", [(1000, "10.2.0.5", "amy", True)], {"login-after-fails", "login-unexpected", "login-from-tor", "login-odd-hour"})


# ---------------------------------------------------------------- ARP
def arp():
    gw = "192.168.1.1"
    base = {gw: ("aa:aa:aa:aa:aa:01", "eth0")}
    for i in range(2, 60):
        base["192.168.1.%d" % i] = ("02:00:00:00:00:%02x" % i, "eth0")
    a = ArpAnalyzer(); fl = n = 0
    for step in range(100):
        t = dict(base)
        if step == 50:                                          # a laptop is replaced: same IP, new MAC (normal)
            base["192.168.1.30"] = ("02:00:00:00:99:30", "eth0"); t = dict(base)
        n += 1; fl += len(a.feed(100 + step * 2, t, gw))
    benign("arp", "59 hosts, one device replaced, 200 s", n, fl)
    a = ArpAnalyzer(); a.feed(100, base, gw)
    t = dict(base); t[gw] = ("ee:ee:ee:ee:ee:ee", "eth0"); t["192.168.1.66"] = ("ee:ee:ee:ee:ee:ee", "eth0")
    ev = a.feed(102, t, gw)
    attack("arp", "gateway MAC replaced by attacker", any(k == "gateway-mac-changed" for k, *_ in ev), "1st table poll (<= poll interval)")
    a = ArpAnalyzer(); a.feed(100, base, gw)
    t = dict(base); t["192.168.1.66"] = ("aa:aa:aa:aa:aa:01", "eth0")                     # attacker copies the gateway MAC, gateway unchanged
    ev = a.feed(102, t, gw)
    attack("arp", "attacker clones the gateway's MAC (gateway entry unchanged)", bool(ev), None, "not detectable from the table alone")


# ---------------------------------------------------------------- sensors
def sensors():
    rnd = random.Random(3)
    g = SensorGuard(); n = fl = 0
    for k in range(600):                                        # 100 temperature sensors, 10 s apart, daily drift + noise
        for i in range(100):
            v = round(24 + 6 * __import__("math").sin(k / 200) + (i % 7) * 0.2 + rnd.gauss(0, 0.3), 1)
            n += 1; fl += len(g.feed({"id": "t%d" % i, "type": "temp_c", "value": v, "ts": float(k * 10), "seq": k + 1, "group": "g%d" % (i // 10)}))
    benign("sensor", "100 temperature sensors, 600 readings each", n, fl)
    def base_guard(secret=None):
        g = SensorGuard(secret=secret)
        for k in range(20):
            for i in range(10):
                g.feed({"id": "s%d" % i, "type": "temp_c", "value": round(25 + i * 0.1 + rnd.gauss(0, 0.2), 1), "ts": float(k * 2), "seq": k + 1, "group": "d"})
        return g
    g = base_guard(); ev = g.feed({"id": "s3", "type": "temp_c", "value": 70.0, "ts": 40.0, "seq": 21, "group": "d"})
    attack("sensor", "out-of-range spike (70 C)", bool(ev), "1st reading")
    g = base_guard(); ev = g.feed({"id": "s3", "type": "temp_c", "value": 31.0, "ts": 40.0, "seq": 21, "group": "d"})
    attack("sensor", "sudden +6 C step in 2 s", bool(ev), "1st reading")
    g = base_guard(); first = None
    for k in range(1, 30):
        ev = g.feed({"id": "s3", "type": "temp_c", "value": 25.3 + 0.8 * k, "ts": 40.0 + k * 2, "seq": 21 + k, "group": "d"})
        for i in (0, 1, 2, 4, 5, 6):
            g.feed({"id": "s%d" % i, "type": "temp_c", "value": round(25 + i * 0.1, 1), "ts": 40.0 + k * 2, "seq": 21 + k, "group": "d"})
        if ev:
            first = k; break
    attack("sensor", "slow drift +0.4 C/s (each step legal)", first is not None, None if first is None else "after %d readings" % first)
    g = base_guard(); first = None
    for k in range(1, 30):
        ev = g.feed({"id": "s3", "type": "temp_c", "value": 25.3, "ts": 40.0 + k * 2, "seq": 21 + k, "group": None})
        if ev: first = k; break
    attack("sensor", "frozen sensor (same value)", first is not None, None if first is None else "after %d readings" % first)
    g = base_guard(); ev = g.feed({"id": "s3", "type": "temp_c", "value": 25.3, "ts": 10.0, "seq": 5, "group": "d"})
    attack("sensor", "replayed old message", bool(ev), "1st reading")
    from sensor_guard import sign
    g = SensorGuard(secret="k")
    r = {"id": "s3", "type": "temp_c", "value": 25.3, "ts": 60.0, "seq": 30, "group": "d"}
    ev = g.feed(dict(r, sig="bad"))
    attack("sensor", "forged message (no valid signature), when signing is on", bool(ev), "1st reading")
    g = base_guard(); ev = g.feed({"id": "s3", "type": "temp_c", "value": 25.9, "ts": 40.0, "seq": 21, "group": "d"})
    attack("sensor", "plausible fake value matching neighbours (+0.6 C)", bool(ev), None, "by design not detectable")


# ---------------------------------------------------------------- ransomware file checks
def ransomware():
    rnd = random.Random(4)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def aes(data):
        return Cipher(algorithms.AES(os.urandom(32)), modes.CTR(os.urandom(16))).encryptor().update(data)
    d = tempfile.mkdtemp(prefix="dseval_")
    def make():
        shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
        import zipfile
        for i in range(30):
            body = "".join("2026-10-19 12:%02d:%02d host%d svc[%d]: request %d user=u%d status=%d\n" % (rnd.randint(0, 59), rnd.randint(0, 59), i, rnd.randint(100, 999), j, rnd.randint(1, 99), rnd.choice([200, 200, 404, 500])) for j in range(400))
            open(os.path.join(d, "doc%d.txt" % i), "w").write(body)
        for i in range(10):
            with zipfile.ZipFile(os.path.join(d, "arch%d.zip" % i), "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("a.txt", "".join(chr(rnd.randint(65, 90)) for _ in range(30000)))
        for i in range(10):
            open(os.path.join(d, "img%d.jpg" % i), "wb").write(b"\xff\xd8\xff\xe0" + os.urandom(40000))
    def flagged(base):
        return {rel: c for p, rel in detect.all_files(d) for c in [detect.check_file(p, rel, base)[0]] if c}
    # benign edits
    make(); base = detect.build_baseline(d)
    for i in range(30):                                            # append a line
        open(os.path.join(d, "doc%d.txt" % i), "a").write("new log line\n")
    f = flagged(base); benign("ransomware", "append to 30 log files", 30, len(f))
    make(); base = detect.build_baseline(d)
    for i in range(30):                                            # edit the first line of a text file
        p = os.path.join(d, "doc%d.txt" % i); s = open(p).read(); open(p, "w").write("# edited\n" + s[10:])
    f = flagged(base); benign("ransomware", "edit the start of 30 text files", 30, len(f), "header check A fires on any change of the first 16 bytes; the vault gate holds such files back, it does not freeze for 1-2 of them")
    make(); base = detect.build_baseline(d)
    import zipfile
    for i in range(10):                                            # re-save a zip with new content
        with zipfile.ZipFile(os.path.join(d, "arch%d.zip" % i), "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", "".join(chr(rnd.randint(65, 90)) for _ in range(30000)))
    f = flagged(base); benign("ransomware", "re-save 10 zip files", 10, len(f))
    # attacks
    variants = {
        "full encryption (AES-CTR, whole file)": lambda b: aes(b),
        "header preserved, rest encrypted": lambda b: b[:64] + aes(b[64:]),
        "first 25% encrypted (partial)": lambda b: aes(b[:len(b) // 4]) + b[len(b) // 4:],
        "first 4 KB only encrypted": lambda b: aes(b[:4096]) + b[4096:],
        "intermittent: 4 KB encrypted every 16 KB": lambda b: b"".join((aes(b[o:o + 4096]) if (o // 4096) % 4 == 0 else b[o:o + 4096]) for o in range(0, len(b), 4096)),
    }
    for name, fn in variants.items():
        make(); base = detect.build_baseline(d)
        files = [rel for _, rel in detect.all_files(d)]
        for rel in files:
            p = os.path.join(d, rel); b = open(p, "rb").read(); open(p, "wb").write(fn(b))
        f = flagged(base)
        text = [r for r in files if r.endswith(".txt")]
        attack("ransomware", name, len(f) >= 3, "%d of %d files flagged (%d of %d text files)" % (len(f), len(files), sum(1 for r in f if r in text), len(text)),
               "kill rule needs 3 flagged files")
    shutil.rmtree(d, ignore_errors=True)


def report():
    L = ["# Dual-Shield evaluation (detection logic, simulated and seeded workloads)\n",
         "Generated by `python3 eval/run_eval.py`. See the notes in that file for what this does and does not measure.\n",
         "## Normal behaviour: false alarms\n", "| Area | Workload | Events | False alarms | Rate | Note |", "|---|---|---|---|---|---|"]
    for b in R["benign"]:
        L.append("| %s | %s | %d | %d | %.2f%% | %s |" % (b["area"], b["case"], b["events"], b["false_alarms"], 100.0 * b["false_alarms"] / max(b["events"], 1), b["note"]))
    L += ["", "## Attacks: detected or missed\n", "| Area | Attack | Detected | When | Note |", "|---|---|---|---|---|"]
    for a in R["attacks"]:
        L.append("| %s | %s | %s | %s | %s |" % (a["area"], a["case"], "YES" if a["detected"] else "**MISSED**", a["latency"] if a["latency"] is not None else "-", a["note"]))
    det = sum(a["detected"] for a in R["attacks"])
    L += ["", "**%d of %d attack cases detected.** The misses are listed on purpose: they are the honest limits of the current rules.\n" % (det, len(R["attacks"]))]
    return "\n".join(L)


if __name__ == "__main__":
    t0 = time.time()
    for fn in (flood, logins, arp, sensors, ransomware):
        fn()
    rep = report()
    open(os.path.join(ROOT, "eval", "REPORT.md"), "w").write(rep)
    json.dump(R, open(os.path.join(ROOT, "eval", "results.json"), "w"), indent=1)
    print(rep)
    print("\n(done in %.1fs)" % (time.time() - t0))
