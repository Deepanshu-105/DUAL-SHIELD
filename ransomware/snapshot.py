"""Periodic integrity snapshot: per-file SHA-256, header bytes, chi-square, Merkle root.

    python3 snapshot.py data/sample_copy --once            # one snapshot
    python3 snapshot.py data/sample_copy --interval 60     # every 60 s

Records only (no file copies), so an attack cannot overwrite a clean copy.
The Merkle root changes if any file's content changes. The clean copy for
rollback is made by rollback.py snapshot.
"""
import argparse, hashlib, json, os, sys, time


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def chi_square(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    e = len(block) / 256.0
    return sum((c - e) ** 2 / e for c in counts)


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def snapshot(folder):
    files = {}
    for root, _, names in os.walk(folder):
        for n in sorted(names):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, folder)
            with open(p, "rb") as f:
                head = f.read(4096)
            files[rel] = {"sha256": sha256(p), "header": head[:16].hex(), "chi2": round(chi_square(head), 1)}
    leaves = [hashlib.sha256((r + ":" + files[r]["sha256"]).encode()).digest() for r in sorted(files)]
    return {"t": time.time(), "folder": folder, "files": len(files), "root": merkle_root(leaves), "detail": files}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=float, default=60.0)
    ap.add_argument("--out", default="evidence/snapshot.log")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    while True:
        s = snapshot(a.folder)
        print("%.3f SNAPSHOT_ROOT %s files=%d" % (s["t"], s["root"], s["files"]), flush=True)
        with open(a.out, "a") as f:
            f.write(json.dumps({k: s[k] for k in ("t", "folder", "files", "root")}) + "\n")
        with open("evidence/snapshot_latest.json", "w") as f:
            json.dump(s, f, indent=1)
        if a.once:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
