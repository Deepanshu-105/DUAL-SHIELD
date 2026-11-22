#!/usr/bin/env python3
"""v13.23: OPT-IN allow-list for benign header rewrites in ransomware/detect.py (check A).   Run from the repo root:  python3 apply_v13_23.py
Default stays OFF, so the frozen results (RESULTS_FROZEN.md) are unchanged. Turn on with  DS_CHECK_A_ALLOW=1  only after the team has read
ransomware/CHECK_A_ALLOWLIST.md and agreed. Nothing is changed unless both anchors match (detect.py.bak is kept)."""
import os, sys
P = "ransomware/detect.py"
NEW_FN = '''
# v13.23 (opt-in, DS_CHECK_A_ALLOW=1): header rewrites that normal programs do, so check A does not flag them.
#   zip family / gzip: the first bytes are the same magic number (only times, sizes and CRCs in the 16-byte header changed)
#   text files: before and after the first 16 bytes are printable text (a title line was added) and the first block still has text-like entropy.
#   Random or encrypted bytes are not printable; base64-armoured ciphertext is printable but too random (> 5.75 bits per byte).
# Trade-off (measured by ransomware/check_a_allow_eval.py): an attacker who keeps the magic number and encrypts everything after it
# is then NOT flagged by check A on zip/gz (check B is blind there anyway: those files were already random).
ZIPLIKE = {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".odt", ".ods"}
TEXTLIKE = {".txt", ".log", ".md", ".csv", ".html", ".htm", ".xml", ".json", ".py", ".c", ".h", ".conf", ".cfg", ".ini", ".sh", ".js", ".css", ".rst", ".yaml", ".yml", ".svg"}

def _printable(b):
    return len(b) > 0 and sum(1 for x in b if x in (9, 10, 13) or 32 <= x < 127) >= len(b) - 1

def _entropy(b):
    import math
    if not b: return 0.0
    n = len(b); c = [0] * 256
    for x in b: c[x] += 1
    return -sum(k / n * math.log2(k / n) for k in c if k)

def benign_header_change(path, old_head_hex, head):
    if os.environ.get("DS_CHECK_A_ALLOW") != "1":
        return False
    ext = os.path.splitext(path)[1].lower()
    old = bytes.fromhex(old_head_hex) if old_head_hex else b""
    if ext in ZIPLIKE:
        return old.startswith(b"PK\\x03\\x04") and head.startswith(b"PK\\x03\\x04")
    if ext == ".gz":
        return old.startswith(b"\\x1f\\x8b\\x08") and head.startswith(b"\\x1f\\x8b\\x08")
    if ext in TEXTLIKE:
        # printable before and after, AND the first block still has the entropy of text (~4-5.5 bits per byte): base64 or hex 'armoured'
        # ciphertext is printable too, but base64 sits near 6 bits, so it is not let through
        return _printable(old) and _printable(head) and _entropy(read_block(path)) <= 5.75
    return False

'''
A1 = "def check_file(path, rel, base):"
A2 = '        if head.hex() != b["header"] or not matches_extension(path, head):\n            return "A", "header changed: %s -> %s" % (b["header"][:16], head.hex()[:16])'
B2 = '        if (head.hex() != b["header"] or not matches_extension(path, head)) and not benign_header_change(path, b["header"], head):\n            return "A", "header changed: %s -> %s" % (b["header"][:16], head.hex()[:16])'
if not os.path.exists(P): sys.exit("%s not found (run from the repo root)" % P)
s = open(P).read()
if "benign_header_change" in s: print("already up to date"); sys.exit(0)
if s.count(A1) != 1 or s.count(A2) != 1: sys.exit("NOTHING CHANGED: anchors not found (detect.py differs from the Nov 14 version)")
s2 = s.replace(A1, NEW_FN.lstrip("\n") + "\n" + A1, 1).replace(A2, B2, 1)
open(P + ".bak", "w").write(s); open(P, "w").write(s2); print("patched", P, "(allow-list is OFF unless DS_CHECK_A_ALLOW=1)")
