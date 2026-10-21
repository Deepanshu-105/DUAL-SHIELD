#!/usr/bin/env python3
"""Replay rows of a CIC-IoT-2023 CSV into CityShield.reportThreat and record gas and time.

The CSVs have no IP column, so each row gets a synthetic address from 198.18.0.0/15
and a fingerprint hashed from its features. This tests the reporting pipeline on
real traffic features. It does not block a real attacker.
"""
import argparse, csv, json, os, statistics, time
from web3 import Web3

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--label", default=None, help="attack class (default: from file name)")
ap.add_argument("--rows", type=int, default=10)
ap.add_argument("--offset", type=int, default=0, help="skip this many rows (use on re-runs)")
ap.add_argument("--confirm", type=int, default=0, help="also report the first N rows from node B")
ap.add_argument("--rpc", default=os.environ.get("CHAIN_HTTP"))
ap.add_argument("--deploy", default=os.path.join(HERE, "..", "deployments", "localhost.json"))
a = ap.parse_args()

dep = json.load(open(a.deploy))
w3 = Web3(Web3.HTTPProvider(a.rpc or dep.get("http", "http://127.0.0.1:8545")))
c = w3.eth.contract(address=Web3.to_checksum_address(dep["address"]), abi=dep["abi"])
node_a, node_b = w3.eth.accounts[1], w3.eth.accounts[2]
label = a.label or os.path.basename(a.csv).split(".")[0]

def synth_ip(i):
    return "198.18.%d.%d" % (i // 250, i % 250 + 1)

def report(ip, fp, who):
    t0 = time.perf_counter()
    tx = c.functions.reportThreat(ip, fp).transact({"from": who})
    rc = w3.eth.wait_for_transaction_receipt(tx)
    ms = (time.perf_counter() - t0) * 1000
    return rc.gasUsed, ms, rc.blockNumber

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
gas, lat, ok, skipped = [], [], 0, 0
with open(out, "w", newline="") as o:
    w = csv.writer(o)
    w.writerow(["row", "ip", "reporter", "gas", "confirm_ms", "block", "status"])
    for i, r in rows:
        ip = synth_ip(i)
        fp = Web3.keccak(text=label + "|" + ",".join(r))
        plan = [("A", node_a)] + ([("B", node_b)] if i - a.offset < a.confirm else [])
        for name, who in plan:
            try:
                g, ms, blk = report(ip, fp, who)
                gas.append(g); lat.append(ms); ok += 1
                w.writerow([i, ip, name, g, "%.1f" % ms, blk, "ok"])
                print("row %d %s node %s gas=%d confirm=%.1f ms block=%d" % (i, ip, name, g, ms, blk))
            except Exception as e:
                skipped += 1
                w.writerow([i, ip, name, "", "", "", "skipped: %s" % str(e)[:60]])
                print("row %d %s node %s SKIPPED: %s" % (i, ip, name, str(e)[:80]))

print("RESULT label=%s rows=%d reports_ok=%d skipped=%d" % (label, len(rows), ok, skipped))
if ok:
    print("RESULT gas_avg=%d gas_max=%d confirm_avg=%.1f ms confirm_max=%.1f ms" %
          (statistics.mean(gas), max(gas), statistics.mean(lat), max(lat)))
print("details:", out)
