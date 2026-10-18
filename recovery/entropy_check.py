import os
import sys
from collections import Counter

# file signatures: extension -> expected starting bytes
MAGIC = {
    ".pdf": b"%PDF",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8",
    ".zip": b"PK\x03\x04",
    ".docx": b"PK\x03\x04",
    ".xlsx": b"PK\x03\x04",
    ".gz": b"\x1f\x8b",
}

# for a 256-bucket test (255 degrees of freedom), random data gives ~255 on average
# a flat/random file lands roughly in 200-310; text and structured files score far higher
RANDOM_LOW, RANDOM_HIGH = 200, 310


def chi_square_bytes(data: bytes) -> float:
    """Chi-square statistic of byte counts versus a uniform distribution."""
    if not data:
        return float("inf")
    expected = len(data) / 256
    counts = Counter(data)
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


def magic_ok(path: str, data: bytes) -> str:
    """Return OK / BAD / n/a depending on whether the header matches the extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in MAGIC:
        return "n/a"
    return "OK" if data.startswith(MAGIC[ext]) else "BAD"


def analyse(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read(1024 * 1024)  # first 1 MB is enough
    chi = chi_square_bytes(data)
    header = magic_ok(path, data)
    looks_random = RANDOM_LOW <= chi <= RANDOM_HIGH
    suspicious = (looks_random and header != "OK") or header == "BAD"
    return {"file": path, "size": len(data), "chi2": chi, "header": header,
            "verdict": "SUSPICIOUS" if suspicious else "clean"}


def main():
    if len(sys.argv) < 2:
        print("usage: python3 entropy_check.py <folder>")
        sys.exit(1)
    print(f"{'file':40} {'size':>9} {'chi2':>12} {'header':>7} verdict")
    for root, _, files in os.walk(sys.argv[1]):
        for name in sorted(files):
            r = analyse(os.path.join(root, name))
            print(f"{name[:40]:40} {r['size']:>9} {r['chi2']:>12.1f} {r['header']:>7} {r['verdict']}")


if __name__ == "__main__":
    main()
