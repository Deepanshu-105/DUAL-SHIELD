import os, statistics, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ssh_parser as sp

sp.chain_report = None            # never send benchmark IPs to the chain
sp.ensure_firewall()
t0 = time.perf_counter()
sp.load_tor()
load_ms = (time.perf_counter() - t0) * 1000

RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 10
drops, looks = [], []
sp.metric = lambda name, ms: (drops if name == "drop_ms" else looks).append(ms)

for i in range(1, RUNS + 1):
    ip = f"198.51.100.{i}"
    subprocess.run(["ipset", "del", "city_blacklist", ip], capture_output=True)
    sp.blocked_ips.discard(ip)
    sp.fail_times.pop(ip, None)
    for _ in range(3):
        sp.record_failure(ip)
    subprocess.run(["ipset", "del", "city_blacklist", ip], capture_output=True)

d, l = statistics.mean(drops), statistics.mean(looks)
print("RESULT runs=%d local_drop_avg=%.2f ms (max %.2f, target <20) "
      "lookup_avg=%.4f ms (max %.4f, target <2) tor_entries=%d tor_load=%.1f ms" %
      (len(drops), d, max(drops), l, max(looks), len(sp.tor_ips), load_ms))
print("PASS" if d < 20 and l < 2 and len(drops) >= 5 else "FAIL")
