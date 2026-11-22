#!/usr/bin/env python3
"""Hardening report for laptop T (target).   sudo python3 multi/check_T.py     (exit 1 if any FAIL)
PASS = fine, WARN = weaker than it should be, FAIL = fix before a real deployment, INFO = cannot be fixed in software here."""
import os, re, stat, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); CFG = os.path.join(HERE, "config.env")
def cfg():
    d = {}
    try:
        for ln in open(CFG):
            m = re.match(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=(.*)$", ln.rstrip("\n"))
            if m: d[m.group(1)] = m.group(2).strip().strip("'\"")
    except OSError: pass
    return d
C = cfg(); rows = []
def add(l, w, f=""): rows.append((l, w, f))
def sh(*a):
    try: r = subprocess.run(a, capture_output=True, text=True, timeout=10); return r.returncode, r.stdout + r.stderr
    except (OSError, subprocess.TimeoutExpired): return 127, ""
def running(pat): return sh("pgrep", "-f", pat)[0] == 0
prod = C.get("PRODUCTION") == "1" or os.environ.get("PRODUCTION") == "1"
try:
    m = stat.S_IMODE(os.stat(CFG).st_mode); add("PASS" if m & 0o077 == 0 else "FAIL", "config.env permissions %o" % m, "chmod 600 multi/config.env")
except OSError: add("FAIL", "multi/config.env missing", "cp multi/config.env.example multi/config.env")
add("PASS" if len(C.get("AGENT_SECRET_T", "")) >= 16 else "FAIL", "agent secret present (16+ chars)", "multi/gen_secrets.sh on D")
add("PASS" if prod else "FAIL", "PRODUCTION=1 (TLS, strict gateway, demo endpoint off, detectors on, blocks kept)", "set PRODUCTION=1 in multi/config.env")
add("PASS" if running("multi/agent.py") else "FAIL", "agent running", "multi/start_T.sh")
add("PASS" if running("ssh_parser.py") else "FAIL", "ssh parser running", "multi/start_T.sh")
for k, pat in (("FLOOD", "flood_detector.py"), ("LOGIN_WATCH", "login_watch.py"), ("ARP_WATCH", "arp_watch.py")):
    on = running(pat); add("PASS" if on else ("WARN" if not prod else "FAIL"), "%s detector running" % k, "start_T.sh starts it when PRODUCTION=1 (or %s=1)" % k)
rc, out = sh("ipset", "list", "city_blacklist"); add("PASS" if rc == 0 else "FAIL", "ipset city_blacklist exists", "multi/start_T.sh")
rc, out = sh("iptables", "-S", "INPUT"); add("PASS" if "city_blacklist" in out else "FAIL", "iptables drops city_blacklist", "multi/start_T.sh / shield_os")
add("PASS" if running("multi/blockkeeper.py") else ("FAIL" if prod else "WARN"), "blockkeeper running (blocks journaled, restored after crash/flush)", "PRODUCTION=1 or KEEP_BLOCKS=1, then multi/start_T.sh")
add("PASS" if running("detector/host_guard.py") else ("FAIL" if prod else "WARN"), "host_guard running (reverse shells, miners)", "PRODUCTION=1 or HOST_GUARD=1, then multi/start_T.sh")
add("PASS" if running("detector/web_guard.py") else "INFO", "web_guard running (only needed if T runs a web server)", "PRODUCTION=1 or WEB_GUARD=1, then multi/start_T.sh")
add("PASS" if running("multi/node_watch.py") else ("FAIL" if prod else "WARN"), "node_watch running (new ports, accounts, keys, cron, modules)", "multi/start_T.sh / start_P.sh start it; baseline: python3 multi/node_watch.py --init")
add("PASS" if running("multi/selfguard.py") or sh("systemctl", "is-active", "dualshield-selfguard")[1].strip() == "active" else "WARN", "selfguard (tamper + outage watch) running", "sudo multi/install_services.sh")
rc, out = sh("iptables", "-S", "INPUT"); add("PASS" if "DUALSHIELD_RL" in out else "WARN", "DDoS floor (rate limits)", "sudo multi/harden_linux.sh apply")
sshd = ""
try: sshd = open("/etc/ssh/sshd_config").read()
except OSError: pass
def sopt(k, bad): m = re.findall(r"^\s*%s\s+(\S+)" % k, sshd, re.M | re.I); return (m[-1].lower() if m else None) != bad
if sshd:
    add("PASS" if sopt("PermitRootLogin", "yes") else "FAIL", "ssh: root login off", "PermitRootLogin no")
    add("PASS" if sopt("PasswordAuthentication", "yes") else "WARN", "ssh: password login off (keys only)", "PasswordAuthentication no")
else: add("INFO", "sshd_config not readable here: ssh settings not checked")
add("PASS" if C.get("AGENT_ALLOW") or prod else "WARN", "agent reachable only from the dashboard laptop", "PRODUCTION=1 (start_T sets AGENT_ALLOW=D_IP)")
vp = os.path.join(ROOT, "ransomware", "data", "vault")
if os.path.isdir(vp):
    st = os.stat(vp); add("PASS" if st.st_uid == 0 and st.st_mode & 0o022 == 0 else "FAIL", "vault owned by root, not group/world writable", "python3 ransomware/protect_vault.py")
add("INFO", "a root attacker can still stop everything (kernel/driver-level protection needs a different product)", "")
w = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
for l, t, f in rows:
    w[l] += 1; print("%-5s %s%s" % (l, t, ("   -> " + f) if f and l in ("FAIL", "WARN") else ""))
print("T CHECK: %d PASS, %d WARN, %d FAIL" % (w["PASS"], w["WARN"], w["FAIL"]))
sys.exit(1 if w["FAIL"] else 0)
