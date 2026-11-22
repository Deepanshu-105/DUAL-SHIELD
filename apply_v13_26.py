#!/usr/bin/env python3
"""v13.26: WriterTracker (kill-rule fallback 'biggest writer') also counts bytes written through write() calls (write_chars), not only disk bytes
(write_bytes). On some kernels (WSL2 seen here) write_bytes stays flat for a process that rewrites a file in a loop, so no writer was found
(KILL_NO_TARGET). Run from the repo root. Nothing changes unless the anchor matches (*.bak kept)."""
import os, sys
P = "multi/shield_os.py"
A = '                cur[p.info["pid"]] = p.io_counters().write_bytes'
B = '                io = p.io_counters()      # v13.26: write_bytes (disk) can stay flat on some kernels (WSL2); write_chars counts every write() call\n                cur[p.info["pid"]] = max(io.write_bytes, getattr(io, "write_chars", 0) or 0)'
try: s = open(P).read()
except OSError: sys.exit(P + " not found (run from the repo root)")
if "v13.26" in s: print("already up to date"); sys.exit(0)
if s.count(A) != 1: sys.exit("NOTHING CHANGED: anchor not found in " + P)
open(P + ".bak", "w").write(s); open(P, "w").write(s.replace(A, B)); print("patched", P)
R = "run_all_tests.sh"
if os.path.exists(R):
    t = open(R).read()
    if "test_writer_tracker" not in t and t.count("multi/test_agent_demo.py") == 1:
        open(R + ".bak", "w").write(t); open(R, "w").write(t.replace("multi/test_agent_demo.py", "multi/test_agent_demo.py multi/test_writer_tracker.py")); print("patched", R)
