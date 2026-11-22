#!/usr/bin/env python3
"""Logic test of win_etw (runs anywhere; feeds fake kernel events). The real ETW part: python win_etw_probe.py on Windows (Administrator)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import win_etw as w
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
root = os.path.join(os.sep, "data", "docs"); w._roots[:] = [os.path.normcase(root) + os.sep]
t = 1000.0
for i in range(6): w.feed(12, 4242, os.path.join(root, "f%d.txt" % i), fobj=100 + i, now=t + i * 0.1)      # create, ransomware pid 4242
for i in range(6): w.feed(16, 4242, fobj=100 + i, now=t + 1)                                              # writes to those file objects
w.feed(12, 777, os.path.join(os.sep, "other", "x.txt"), fobj=900, now=t); w.feed(16, 777, fobj=900, now=t)  # outside the folder
w.feed(12, 555, os.path.join(root, "one.txt"), fobj=500, now=t)                                           # a single create only
check("heavy writer under the folder is found", w.writers_under(now=t + 2) == {4242})
check("process writing elsewhere is ignored", 777 not in w.writers_under(now=t + 2))
check("a single operation is below the threshold", 555 not in w.writers_under(now=t + 2))
check("old activity expires after the window", w.writers_under(now=t + 60) == set())
sys.exit(1 if bad else 0)
