#!/usr/bin/env python3
"""Backup codes for the dashboard 2-step sign-in (phone lost or broken). Each code works ONCE in the 'code' field instead of the 6-digit number.
   python3 multi/make_backup_codes.py          make 8 new codes (old ones stop working), shown ONCE: write them on paper, keep them away from this machine
   python3 multi/make_backup_codes.py --off    remove them
Only SHA-256 hashes go into multi/config.env (DASH_BACKUP_CODES). Used codes are remembered in multi/logs/dashboard_backup_used.txt. Restart the dashboard afterwards."""
import base64, hashlib, os, re, secrets, stat, sys
HERE = os.path.dirname(os.path.abspath(__file__)); CFG = os.path.join(HERE, "config.env")
if not os.path.exists(CFG): sys.exit("multi/config.env not found")
def h(c): return hashlib.sha256(("ds-backup|" + re.sub(r"[^a-z2-7]", "", c.lower())).encode()).hexdigest()
def save(val):
    txt = open(CFG).read(); line = "DASH_BACKUP_CODES=" + val
    txt = re.sub(r"^DASH_BACKUP_CODES=.*$", lambda _: line, txt, flags=re.M) if re.search(r"^DASH_BACKUP_CODES=", txt, re.M) else txt.rstrip("\n") + "\n" + line + "\n"
    open(CFG, "w").write(txt); os.chmod(CFG, stat.S_IRUSR | stat.S_IWUSR)
if "--off" in sys.argv: save(""); sys.exit("backup codes removed. Restart the dashboard.")
codes = []
for _ in range(8):
    raw = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=").lower()[:12]      # 60 bits
    codes.append(raw[:4] + "-" + raw[4:8] + "-" + raw[8:])
save(",".join(h(c) for c in codes))
try: os.remove(os.path.join(HERE, "logs", "dashboard_backup_used.txt"))
except OSError: pass
print("Backup codes (shown ONCE; each works one time in the 'code' field; do not photograph or paste them):\n")
for c in codes: print("    " + c)
print("\nSaved as hashes in multi/config.env. Restart the dashboard (multi/start_D.sh).")
