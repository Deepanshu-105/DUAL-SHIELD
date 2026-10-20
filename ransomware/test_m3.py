"""End-to-end M3 test. Run from the ransomware/ folder:

    python3 test_m3.py            # 10 runs
    python3 test_m3.py 20 0.05    # 20 runs, 0.05 s per-file delay in the simulator

Each run: restore clean copy -> start watcher with kill rule -> start mock_crypto
-> measure (3rd-flag -> process dead) -> count damaged files -> rollback -> verify.
"""
import csv, os, re, signal, subprocess, sys, time
import rollback

RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 10
DELAY = sys.argv[2] if len(sys.argv) > 2 else "0.05"
SRC, COPY = "data/sample", "data/sample_copy"
LOG = "evidence/watch.log"
os.makedirs("evidence", exist_ok=True)

subprocess.run([sys.executable, "detect.py", "baseline", SRC], check=True)
manifest = rollback.take_snapshot(SRC)          # pre-attack snapshot, once

rows = []
for i in range(1, RUNS + 1):
    rollback.restore(COPY)                      # clean state before every run
    open(LOG, "w").close()
    watcher = subprocess.Popen([sys.executable, "detect.py", "watch", COPY, "--kill"],
                               stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
    for _ in range(100):                        # wait until the watcher is up
        if "watching" in open(LOG).read():
            break
        time.sleep(0.05)
    time.sleep(0.3)                             # let inotify settle

    t_start = time.time()
    atk = subprocess.Popen([sys.executable, "mock_crypto.py", COPY, "--delay", DELAY],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atk.wait()
    t_dead = time.time()
    time.sleep(0.3)                             # let the watcher flush its log
    watcher.send_signal(signal.SIGINT); watcher.wait(timeout=5)

    log = open(LOG).read()
    m = re.search(r"([\d.]+) KILL_TRIGGER", log)
    flagged = len(re.findall(r"FLAGGED", log))
    got = rollback.hash_folder(COPY)
    damaged = sum(1 for k, v in manifest.items() if got.get(k) != v)
    latency_ms = (t_dead - float(m.group(1))) * 1000 if m else None

    t0 = time.perf_counter()
    rollback.restore(COPY)
    ok, bad = rollback.verify(COPY)
    rb_ms = (time.perf_counter() - t0) * 1000

    rows.append(dict(run=i, killed=atk.returncode == -9, kill_latency_ms=latency_ms,
                     flags_logged=flagged, files_damaged=damaged,
                     total_files=len(manifest), rollback_ok=ok, rollback_ms=rb_ms))
    print("run %2d: rc=%s latency=%s ms flags=%d damaged=%d/%d rollback=%s (%.0f ms)\n" % (
        i, atk.returncode, "%.1f" % latency_ms if latency_ms is not None else "NO TRIGGER",
        flagged, damaged, len(manifest), "OK" if ok else "FAIL", rb_ms))

with open("evidence/m3_results.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)

lat = [r["kill_latency_ms"] for r in rows if r["kill_latency_ms"] is not None]
print("=== SUMMARY (%d runs, simulator delay %s s/file) ===" % (RUNS, DELAY))
print("killed with SIGKILL:   %d / %d" % (sum(r["killed"] for r in rows), RUNS))
if lat:
    print("kill latency ms:       min %.1f  mean %.1f  max %.1f   (target < 100)" % (min(lat), sum(lat) / len(lat), max(lat)))
print("files damaged at kill: %s of %d" % (sorted({r["files_damaged"] for r in rows}), len(manifest)))
print("rollback hash match:   %d / %d runs" % (sum(r["rollback_ok"] for r in rows), RUNS))
