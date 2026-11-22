#!/usr/bin/env python3
"""Hardening report for laptop D (dashboard + chain + gateway).   python3 multi/check_D.py     (exit 1 if any FAIL)
PASS = fine, WARN = works but is weaker than it should be, FAIL = must be fixed before a real deployment, INFO = cannot be fixed in software here."""
import json, os, re, stat, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
CFG = os.path.join(HERE, "config.env"); ENC = os.path.join(HERE, "secrets.enc")
def cfg():
    d = {}
    try:
        for ln in open(CFG):
            m = re.match(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=(.*)$", ln.rstrip("\n"))
            if m: d[m.group(1)] = m.group(2).strip().strip("'\"")
    except OSError: pass
    return d
C = cfg(); sealed = os.path.exists(ENC); rec = False
try: rec = "rec" in json.load(open(ENC))
except Exception: pass
rows = []
def add(level, what, fix=""): rows.append((level, what, fix))
prod = C.get("PRODUCTION") == "1" or os.environ.get("PRODUCTION") == "1"
tls = C.get("TLS") == "1" or prod
try:
    mode = stat.S_IMODE(os.stat(CFG).st_mode); add("PASS" if mode & 0o077 == 0 else "FAIL", "config.env permissions %o" % mode, "chmod 600 multi/config.env")
except OSError: add("FAIL", "multi/config.env missing", "cp multi/config.env.example multi/config.env")
add("PASS" if tls else "FAIL", "TLS for the dashboard and the gateway", "set PRODUCTION=1 (or TLS=1) in multi/config.env")
crt = os.path.join(HERE, "tls", "dashboard", "node.crt")
if tls:
    if not os.path.exists(crt): add("FAIL", "TLS certificate for D not found", "multi/make_tls.sh (start_D does it itself when PRODUCTION=1)")
    else:
        ok = subprocess.run(["openssl", "x509", "-checkend", str(30 * 86400), "-noout", "-in", crt], capture_output=True).returncode == 0
        add("PASS" if ok else "WARN", "TLS certificate valid for 30+ more days" if ok else "TLS certificate expires within 30 days (or is expired)", "multi/make_tls.sh --rotate  (see README_V13_12)")
add("PASS" if C.get("GATEWAY_LAB", "1") == "0" or prod else "FAIL", "gateway strict mode (each laptop only its own Fabric identity)", "PRODUCTION=1 or GATEWAY_LAB=0 (then P must report for itself: COREPORT=0)")
add("PASS" if sealed else "FAIL", "passwords sealed (secrets.enc)", "python3 multi/secrets_vault.py seal")
add("PASS" if rec else ("WARN" if sealed else "INFO"), "recovery key for the sealed secrets" if rec else "no recovery key for the sealed secrets", "python3 multi/secrets_vault.py recovery-key")
totp = len(C.get("DASH_TOTP_SECRET", "")) >= 16
add("PASS" if totp else ("WARN" if sealed else "FAIL"), "2-step sign-in" if totp else ("2-step sign-in (value is sealed; cannot be checked here)" if sealed else "2-step sign-in is off"), "python3 multi/make_totp.py")
add("PASS" if C.get("DASH_BACKUP_CODES") else "WARN", "backup codes for a lost phone", "python3 multi/make_backup_codes.py")
add("PASS" if (C.get("DASH_AUDIT_MIRROR") or C.get("DASH_AUDIT_WEBHOOK")) else "FAIL", "audit log has a second copy (mirror or webhook)", "set DASH_AUDIT_MIRROR=/mnt/other_disk/audit.jsonl or DASH_AUDIT_WEBHOOK=https://...")
bdir = os.path.expanduser(C.get("LEDGER_BACKUP_DIR", "~/dualshield_backups"))
try:
    fs = [os.path.join(bdir, f) for f in os.listdir(bdir) if f.endswith(".enc")]
    age = (time.time() - max(os.path.getmtime(f) for f in fs)) / 86400
    add("PASS" if age <= 7 else "WARN", "newest ledger backup is %.1f days old" % age, "fabric/deploy/backup_ledger.sh  (put it in cron)")
except (OSError, ValueError): add("FAIL", "no ledger backup found in " + bdir, "fabric/deploy/backup_ledger.sh")
add("PASS" if C.get("DASH_TRUST_PROXY") == "1" else "INFO", "client addresses are real behind the TLS front" if C.get("DASH_TRUST_PROXY") == "1" else "rate limits see the TLS tunnel as one client (set DASH_TRUST_PROXY=1 only behind a real reverse proxy)", "")
tf = os.path.join(HERE, "logs", "peer_trust.json")
try:
    age = time.time() - json.load(open(tf)).get("updated", 0)
    add("PASS" if age < 120 else "WARN", "peer trust monitor running (watches the nodes themselves)" if age < 120 else "peer trust monitor state is %d s old: it is not running" % age, "start_D.sh starts it; or python3 network/peer_trust.py")
except (OSError, ValueError): add("WARN", "peer trust monitor has not run yet (start_D.sh starts it)", "multi/start_D.sh")
add("INFO", "chain runs on this one machine: orderers/peers on other machines are an infrastructure step (README_V13_12)", "")
add("INFO", "a root attacker on D can still stop the dashboard: run multi/watch_dashboard.py on ANOTHER laptop (--print-autostart)", "")
add("INFO", "secrets exist in memory while running (HSM / secret manager not available in software)", "")
if "--start" in sys.argv:          # at start the first backup cannot exist yet: it is a warning there, not a blocker
    rows = [("WARN", r[1], r[2]) if (r[0] == "FAIL" and "ledger backup" in r[1]) else r for r in rows]
w = max(len(r[1]) for r in rows)
for lv, what, fix in rows: print("%-5s %-*s %s" % (lv, w, what, ("-> " + fix) if fix and lv in ("FAIL", "WARN") else ""))
n = {k: sum(1 for r in rows if r[0] == k) for k in ("PASS", "WARN", "FAIL", "INFO")}
print("\n%d PASS, %d WARN, %d FAIL, %d INFO" % (n["PASS"], n["WARN"], n["FAIL"], n["INFO"])); sys.exit(1 if n["FAIL"] else 0)
