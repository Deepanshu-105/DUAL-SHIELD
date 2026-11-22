#!/usr/bin/env python3
"""Keeps the blocks on T/P real.   python3 multi/blockkeeper.py [--restore] [--once]

Every BK_EVERY seconds (default 5) compares the journal of blocks that SHOULD exist (shield_os, written before every block)
with the real firewall. A block that vanished (ipset del / flush / reboot) and a missing iptables DROP rule are put back and
logged as BLOCKKEEPER_TAMPER (also readable by D through the signed agent: log name "keeper"). --restore applies the journal once
(start of T after a crash or reboot). Honest limit: root can stop this process too; D's liveness audit then reports the laptop.
"""
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import shield_os
EVERY = float(os.environ.get("BK_EVERY", "5"))


class Keeper:
    def __init__(self, desired, actual, add, rule_ok, repair_rule, log=print, now=time.time):
        self.desired, self.actual, self.add, self.rule_ok, self.repair_rule, self.log, self.now = desired, actual, add, rule_ok, repair_rule, log, now
    def tick(self):
        fixed = 0
        if not self.rule_ok():
            self.repair_rule(); fixed += 1
            self.log("BLOCKKEEPER_TAMPER the iptables DROP rule was missing: restored")
        have = set(self.actual())
        for ip in sorted(self.desired() - have):
            self.add(ip); fixed += 1
            self.log("BLOCKKEEPER_TAMPER block of %s had been removed outside DualShield: restored" % ip)
        return fixed
    def restore(self):
        n = 0
        for ip in sorted(self.desired()):
            self.add(ip); n += 1
        return n


def real():
    rule = ["INPUT", "-m", "set", "--match-set", shield_os.SET, "src", "-j", "DROP"]
    def rule_ok(): return shield_os._run(["iptables", "-C", *rule]).returncode == 0
    def logline(m):
        line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), m); print(line, flush=True)
        try:
            with open(shield_os.log_path("keeper.log"), "a") as f: f.write(line + "\n")
        except OSError: pass
    return Keeper(shield_os.desired_load, shield_os.block_list, shield_os.block_add, rule_ok, shield_os.block_init, logline)


if __name__ == "__main__":
    shield_os.block_init(); k = real()
    if "--restore" in sys.argv:
        print("BLOCKKEEPER restored %d block(s) from the journal" % k.restore(), flush=True)
    if "--once" in sys.argv: sys.exit(0)
    print("BLOCKKEEPER on (every %g s)" % EVERY, flush=True)
    while True:
        try: k.tick()
        except Exception as e: print("BLOCKKEEPER error: %s" % e, flush=True)
        time.sleep(EVERY)
