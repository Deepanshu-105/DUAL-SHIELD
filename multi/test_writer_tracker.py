#!/usr/bin/env python3
"""v13.26: the 'biggest writer' fallback works when the kernel reports write_chars but a flat write_bytes (WSL2), and still works with write_bytes only."""
import os, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shield_os as so
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
IO = collections.namedtuple("IO", "write_bytes write_chars")
IO2 = collections.namedtuple("IO2", "write_bytes")
class Proc:
    def __init__(self, pid, name, ioseq): self.info = {"pid": pid, "name": name}; self.seq = ioseq
    def io_counters(self): return self.seq.pop(0)
class FakePs:
    def __init__(self, procs): self.procs = procs
    def process_iter(self, attrs): return iter(self.procs)
def run(seq_writer, seq_idle):
    ps = FakePs([Proc(111, "cryptor", list(seq_writer)), Proc(222, "idle", list(seq_idle))]); so._psutil = lambda: ps
    t = so.WriterTracker(); t.sample(); return t.sample()
check("flat write_bytes but growing write_chars (WSL2): the writer is found", run([IO(0, 100), IO(0, 5000000)], [IO(0, 10), IO(0, 10)]) == [111])
check("write_bytes only (old psutil / Windows): still found", run([IO2(100), IO2(5000000)], [IO2(1), IO2(1)]) == [111])
check("nobody writing: nothing returned (no innocent process is named)", run([IO(0, 10), IO(0, 10)], [IO(0, 5), IO(0, 5)]) == [])
sys.exit(1 if bad else 0)
