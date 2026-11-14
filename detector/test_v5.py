#!/usr/bin/env python3
"""Tests for the v5 hardening pieces: IP privacy on chain, CIDR never-block list, defender self-watch."""
import os, subprocess, sys, shutil
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path[:0] = [HERE, os.path.join(ROOT, "network")]
bad = []
def check(name, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + name, "" if ok else extra)
    if not ok: bad.append(name)

# --- NetSet
from netset import NetSet
n = NetSet(["10.0.0.0/8", "192.168.1.5", "2001:db8::/32", "", "junk"])
check("CIDR contains", "10.9.8.7" in n)
check("single IP contains", "192.168.1.5" in n and "192.168.1.6" not in n)
check("outside not contained", "8.8.8.8" not in n)
check("IPv6 CIDR", "2001:db8::1" in n)
check("garbage ignored, no crash", "not-an-ip" not in n)
check("empty set falsy", not NetSet([]))

# --- ipcrypt
os.environ["CHAIN_IP_KEY"] = "test-key-1"
import importlib, ipcrypt; importlib.reload(ipcrypt)
e = ipcrypt.encode("198.51.100.9")
check("encoded hides the IP", e.startswith("enc1:") and "198.51" not in e)
check("deterministic (same IP same token)", e == ipcrypt.encode("198.51.100.9"))
check("different IPs differ", e != ipcrypt.encode("198.51.100.10"))
check("round trip", ipcrypt.decode(e) == "198.51.100.9")
check("no double encoding", ipcrypt.encode(e) == e)
check("plain passes through decode", ipcrypt.decode("1.2.3.4") == "1.2.3.4")
os.environ["CHAIN_IP_KEY"] = "other-key"; importlib.reload(ipcrypt)
check("wrong key cannot read", ipcrypt.decode(e) is None)
os.environ.pop("CHAIN_IP_KEY"); importlib.reload(ipcrypt)
check("no key: plain IPs (unchanged behaviour)", ipcrypt.encode("1.2.3.4") == "1.2.3.4")

# --- selfguard
sg = os.path.join(ROOT, "multi", "selfguard.py")
man = os.path.join(ROOT, "ransomware", "evidence", "selfguard.manifest.json")
victim = os.path.join(ROOT, "detector", "_sg_victim.py")
env = dict(os.environ, SELFGUARD_KEY="k1")
def run(*a): return subprocess.run([sys.executable, sg, *a], env=env, capture_output=True, text=True, cwd=ROOT)
had = os.path.exists(man); saved = open(man).read() if had else None
try:
    open(victim, "w").write("x=1\n")
    run("--init")
    check("clean check passes", run("--check").returncode == 0, run("--check").stdout)
    open(victim, "w").write("x=2  # tampered\n")
    r = run("--check"); check("modified file detected", r.returncode == 1 and "SELFGUARD_TAMPER" in r.stdout, r.stdout)
    open(victim, "w").write("x=1\n"); os.remove(victim)
    r = run("--check"); check("removed file detected", r.returncode == 1, r.stdout)
    run("--init"); open(victim, "w").write("x=1\n")
    r = run("--check"); check("added file detected", r.returncode == 1 and "NEW_FILE" in r.stdout, r.stdout)
    os.remove(victim)
    run("--init")
    r = subprocess.run([sys.executable, sg, "--check"], env=dict(os.environ, SELFGUARD_KEY="wrong"), capture_output=True, text=True, cwd=ROOT)
    check("manifest re-signed with a different key is rejected", r.returncode == 1, r.stdout)
finally:
    if os.path.exists(victim): os.remove(victim)
    if had: open(man, "w").write(saved)
    elif os.path.exists(man): os.remove(man)
print("ALL PASS" if not bad else "SOME FAILED: %s" % bad); sys.exit(1 if bad else 0)
