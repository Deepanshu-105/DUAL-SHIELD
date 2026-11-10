#!/usr/bin/env python3
"""v12 checks: fanotify kernel writer hook (skipped, not failed, when not root/unsupported), hardening script dry-run, killrule uses kernel pids."""
import os, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import shield_os
ok = True
def check(name, cond):
    global ok; print(("PASS " if cond else "FAIL ") + name); ok &= bool(cond)

d = tempfile.mkdtemp()
k = shield_os.KernelWriters(d)
if k.ok:
    p = subprocess.Popen(["sh", "-c", "echo x > %s/a.txt; sleep 1" % d]); time.sleep(0.7)
    check("fanotify reports the writing pid", p.pid in k.writers())
    check("own process is not reported", os.getpid() not in k.writers())
    p.wait()
else:
    print("SKIP fanotify (needs root + kernel support)")

r = subprocess.run(["bash", os.path.join(HERE, "harden_linux.sh"), "apply", "--dry-run"], capture_output=True, text=True)
check("harden dry-run exits 0", r.returncode == 0)
check("harden: syn cookies + hashlimit + connlimit", all(s in r.stdout for s in ("tcp_syncookies=1", "hashlimit", "connlimit")))
check("harden: chattr +i and Restart units", "chattr +i" in r.stdout and "dualshield-guard.service" in r.stdout)
unit = subprocess.run(["bash", "-c", "UNITDIR=%s bash %s apply --dry-run" % (d, os.path.join(HERE, "harden_linux.sh"))], capture_output=True, text=True)
check("harden dry-run writes nothing", not [f for f in os.listdir(d) if f.endswith(".service")])
src = open(os.path.join(HERE, "..", "ransomware", "killrule.py")).read()
check("killrule prefers kernel-fanotify pids", "kernel-fanotify" in src and "KERNEL_HOOK" in src)
print("ALL PASS" if ok else "SOME FAILED"); sys.exit(0 if ok else 1)
