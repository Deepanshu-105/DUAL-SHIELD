#!/usr/bin/env python3
"""Check the dashboard audit log from outside the dashboard: every line must carry the hash of the line before it, and the mirror must equal the original.
   python3 multi/verify_audit.py [audit.jsonl] [mirror.jsonl]      (defaults: multi/logs/dashboard_audit.jsonl and $DASH_AUDIT_MIRROR)"""
import hashlib, json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
main = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "logs", "dashboard_audit.jsonl")
mir = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("DASH_AUDIT_MIRROR", "")
def chain(path):
    prev, n = "0" * 64, 0
    for i, l in enumerate(open(path).read().strip().split("\n")):
        if not l: continue
        e = json.loads(l); h = e.pop("h")
        if e.get("prev") != prev or hashlib.sha256(json.dumps(e, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() != h: return "BROKEN at line %d" % (i + 1)
        prev, n = h, n + 1
    return "OK (%d lines)" % n
print("audit log :", chain(main))
if mir and os.path.exists(mir):
    print("mirror    :", chain(mir))
    a, b = open(main).read(), open(mir).read()
    print("mirror vs original:", "identical" if a == b else "DIFFERENT: lines were removed or changed in one of the two files (the mirror holding more lines means the original was cut)")
else:
    print("mirror    : not set or missing")
