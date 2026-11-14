#!/usr/bin/env python3
"""Replay rows of a CIC-IoT-2023 CSV into the CityShield chaincode's reportThreat and record commit time (Fabric has no gas).

The CSVs have no IP column, so each row gets a synthetic address from 198.18.0.0/15
and a fingerprint hashed from its features. This tests the reporting pipeline on
real traffic features. It does not block a real attacker.
"""
import argparse, csv, hashlib, os, statistics, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "network"))
from chainlib import Chain

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--label", default=None, help="attack class (default: from file name)")
ap.add_argument("--rows", type=int, default=10)
ap.add_argument("--offset", type=int, default=0, help="skip this many rows (use on re-runs)")
ap.add_argument("--confirm", type=int, default=0, help="also report the first N rows from node B")
ap.add_argument("--gateway", default=os.environ.get("GATEWAY_URL"))
a = ap.parse_args()

chain = Chain(a.gateway)
node_a, node_b = 1, 2                          # Fabric identities: target node (Org1 User1), peer node (Org2 User1)
label = a.label or os.path.basename(a.csv).split(".")[0]

def synth_ip(i):
    return "198.18.%d.%d" % (i // 250, i % 250 + 1)

def report(ip, fp, who):
    t0 = time.perf_counter()
    chain.submit(who, "reportThreat", ip, fp)  # returns after the transaction is committed
    return (time.perf_counter() - t0) * 1000

rows = []
with open(a.csv, newline="") as f:
    rd = csv.reader(f)
    next(rd)                                   # header
    for i, r in enumerate(rd):
        if i < a.offset:
            continue
        if len(rows) >= a.rows:
            break
        rows.append((i, r))

os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
out = os.path.join(HERE, "results", "replay_%d.csv" % int(time.time()))
lat, ok, skipped = [], 0, 0
with open(out, "w", newline="") as o:
    w = csv.writer(o)
    w.writerow(["row", "ip", "reporter", "commit_ms", "status"])
    for i, r in rows:
        ip = synth_ip(i)
        fp = hashlib.sha256((label + "|" + ",".join(r)).encode()).hexdigest()
        plan = [("A", node_a)] + ([("B", node_b)] if i - a.offset < a.confirm else [])
        for name, who in plan:
            try:
                ms = report(ip, fp, who)
                lat.append(ms); ok += 1
                w.writerow([i, ip, name, "%.1f" % ms, "ok"])
                print("row %d %s node %s commit=%.1f ms" % (i, ip, name, ms))
            except Exception as e:
                skipped += 1
                w.writerow([i, ip, name, "", "skipped: %s" % str(e)[:60]])
                print("row %d %s node %s SKIPPED: %s" % (i, ip, name, str(e)[:80]))

print("RESULT label=%s rows=%d reports_ok=%d skipped=%d" % (label, len(rows), ok, skipped))
if ok:
    print("RESULT no gas (Fabric); commit_avg=%.1f ms commit_max=%.1f ms" % (statistics.mean(lat), max(lat)))
print("details:", out)
