#!/usr/bin/env python3
"""
Phase 1: Baseline snapshot.
For every file in the protected folder, store its header bytes and its
baseline chi-square result. Phase 5's watchdog compares live files against
this snapshot rather than judging them in isolation.
"""

import os
import sys
import json
import time
from collections import Counter

BLOCK_SIZE = 4096
CHI_SQUARE_THRESHOLD = 310.46  # p > 0.01, df = 255
HEADER_BYTES = 16


def chi_square_bytes(data: bytes) -> float:
    if not data:
        return float("inf")
    expected = len(data) / 256
    counts = Counter(data)
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


def snapshot_file(path: str) -> dict:
    with open(path, "rb") as f:
        head = f.read(HEADER_BYTES)
        f.seek(0)
        block = f.read(BLOCK_SIZE)

    chi2 = chi_square_bytes(block)
    was_nonuniform = chi2 >= CHI_SQUARE_THRESHOLD

    return {
        "header_hex": head.hex(),
        "baseline_chi_square": round(chi2, 2),
        "was_nonuniform": was_nonuniform,
        "snapshot_time": time.time(),
    }


def build_snapshot(folder: str) -> dict:
    snapshot = {}
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if os.path.isfile(path):
            snapshot[name] = snapshot_file(path)
    return snapshot


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "recovery/samples"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "recovery/baseline_snapshot.json"

    snapshot = build_snapshot(folder)

    with open(out_path, "w") as f:
        json.dump(snapshot, f, indent=2)

    print(f"Snapshot of {len(snapshot)} files written to {out_path}")
    nonuniform = sum(1 for v in snapshot.values() if v["was_nonuniform"])
    uniform = len(snapshot) - nonuniform
    print(f"  {nonuniform} files were non-uniform at baseline (normal files)")
    print(f"  {uniform} files were already uniform at baseline (compressed, or stand-in encrypted)")


if __name__ == "__main__":
    main()
