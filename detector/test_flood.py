"""Tests for flood_detector.py and expire_blocks.py.  python3 detector/test_flood.py"""
import os, socket, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import expire_blocks
from flood_detector import FloodAnalyzer, Reactor, capture, mitigation_commands

ok_all = True


def check(name, cond, extra=""):
    global ok_all
    ok_all &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("  " + str(extra) if extra else ""))


def kinds(evs):
    return sorted({(k, ip) for k, ip, _ in evs})


# 1. one loud source -> syn-flood, flagged once
a = FloodAnalyzer(syn_rate=100, window=2.0)
evs = []
for i in range(400):
    evs += a.feed(100 + i * 0.005, "198.51.100.9", 80, "tcp", True)
check("syn-flood detected once", kinds(evs) == [("syn-flood", "198.51.100.9")], kinds(evs))

# 2. normal browsing is not flagged
a = FloodAnalyzer()
evs = []
for i in range(60):
    evs += a.feed(100 + i * 0.5, "198.51.100.10", 443, "tcp", True)      # 2 connections/s
    evs += a.feed(100 + i * 0.5, "198.51.100.10", 443, "tcp", False)     # established traffic is not counted
check("normal traffic not flagged", not evs, kinds(evs))

# 3. port scan: slow, few packets, many ports
a = FloodAnalyzer(scan_ports=20, scan_window=10)
evs = []
for i in range(30):
    evs += a.feed(100 + i * 0.2, "198.51.100.11", 1000 + i, "tcp", True)
check("port-scan detected", kinds(evs) == [("port-scan", "198.51.100.11")], kinds(evs))

# 4. udp flood
a = FloodAnalyzer(udp_rate=300, window=2)
evs = []
for i in range(1500):
    evs += a.feed(100 + i * 0.001, "198.51.100.12", 53, "udp")
check("udp-flood detected", ("udp-flood", "198.51.100.12") in kinds(evs), kinds(evs))

# 5. botnet: 60 sources, each quiet (below the per-source limit), together loud
a = FloodAnalyzer(syn_rate=100, total_rate=400, min_sources=15, window=2)
evs = []
for i in range(1200):
    evs += a.feed(100 + i * 0.001, "203.0.113.%d" % (i % 60 + 1), 80, "tcp", True)
ks = kinds(evs)
check("botnet mode announced", ("botnet", "*") in ks, ks[:3])
check("top talkers reported, no per-source syn-flood", all(k == "botnet" for k, _ in ks) and len(ks) >= 2, len(ks))

# 6. whitelist
a = FloodAnalyzer(whitelist={"172.30.0.11"})
evs = []
for i in range(1000):
    evs += a.feed(100 + i * 0.001, "172.30.0.11", 80, "tcp", True)
check("whitelisted dashboard/peer never flagged", not evs)

# 7. mitigation command is a plain hashlimit rule
check("mitigation rule", "hashlimit" in mitigation_commands()[0])

# 8. live capture on loopback (needs root + AF_PACKET); dry mode, nothing is blocked
try:
    stop = threading.Event()
    an = FloodAnalyzer(syn_rate=50, window=1.0, whitelist=set())
    rx = Reactor(dry=True, apply_mit=False, whitelist=set(), chain=False)
    t = threading.Thread(target=capture, args=("lo", an, rx, stop), daemon=True)
    t.start()
    time.sleep(0.5)
    end = time.time() + 1.5
    while time.time() < end:                                   # connection attempts to a closed port = SYNs
        for _ in range(30):
            s = socket.socket()
            s.settimeout(0.01)
            try:
                s.connect(("127.0.0.1", 9))
            except OSError:
                pass
            s.close()
    time.sleep(0.5)
    stop.set()
    check("live capture on lo sees the flood", "127.0.0.1" in rx.blocked, rx.blocked)
except PermissionError:
    print("SKIP live capture (needs root)")

# 9. expiry: only blocks older than the TTL are removed; an unblock cancels
d = tempfile.mkdtemp()
lg = os.path.join(d, "b.log")
now = time.time()
open(lg, "w").write("PARSER_BLOCK ip=1.1.1.1 ts=%.3f\nPEER_BLOCK ip=2.2.2.2 ts=%.3f\nFLOOD_BLOCK ip=3.3.3.3 ts=%.3f kind=x\n"
                    "PEER_BLOCK ip=4.4.4.4 ts=%.3f\nPEER_UNBLOCK ip=4.4.4.4 ts=%.3f reason=overruled\n"
                    % (now - 7200, now - 10, now - 5000, now - 9000, now - 8000))
check("expiry picks only old blocks", expire_blocks.expired(expire_blocks.latest_block_times([lg]), 3600) == ["1.1.1.1", "3.3.3.3"])

print("\nALL PASS" if ok_all else "\nSOME FAILED")
sys.exit(0 if ok_all else 1)
