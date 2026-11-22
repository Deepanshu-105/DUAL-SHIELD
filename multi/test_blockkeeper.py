#!/usr/bin/env python3
import os, sys, tempfile
os.environ["SHIELD_LOGDIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shield_os, blockkeeper
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
fw = set(); rule = [True]; logs = []
add = lambda ip: fw.add(ip)
k = blockkeeper.Keeper(lambda: {"203.0.113.1", "203.0.113.2"}, lambda: list(fw), add, lambda: rule[0], lambda: rule.__setitem__(0, True), logs.append)
check("restore puts the journal back after a crash/reboot", k.restore() == 2 and fw == {"203.0.113.1", "203.0.113.2"})
check("nothing changed = nothing fixed", k.tick() == 0 and not logs)
fw.discard("203.0.113.2"); check("block removed behind our back is restored and logged", k.tick() == 1 and "203.0.113.2" in fw and "BLOCKKEEPER_TAMPER" in logs[-1])
fw.clear(); rule[0] = False; n = k.tick(); check("flush + removed DROP rule: all restored", n == 3 and len(fw) == 2 and rule[0])
if not shield_os.IS_WIN:
    calls = []; shield_os._run = lambda cmd, check=False: calls.append(cmd) or type("R", (), {"returncode": 0, "stdout": ""})()
    shield_os.block_add("203.0.113.9"); check("journal is written when a block is added", "203.0.113.9" in shield_os.desired_load() and calls)
    shield_os.block_del("203.0.113.9"); check("journal entry removed on a legitimate unblock (no false alarm)", "203.0.113.9" not in shield_os.desired_load())
    shield_os.block_add("203.0.113.8"); shield_os.block_flush(); check("flush through DualShield clears the journal", shield_os.desired_load() == set())
sys.exit(1 if bad else 0)
