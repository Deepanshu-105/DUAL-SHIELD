#!/usr/bin/env python3
"""v13.11 checks: one-time backup codes, per-path roles, secrets recovery key. Needs node and 'cryptography'."""
import os, pty, re, shutil, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
T = tempfile.mkdtemp(); M = os.path.join(T, "multi"); os.makedirs(M)
for f in ("make_backup_codes.py", "secrets_vault.py"): shutil.copy(os.path.join(HERE, f), M)
open(os.path.join(M, "config.env"), "w").write("DASH_PASS=adminpass123\nDASH_BACKUP_CODES=\nDASH_TOTP_SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\nDASH_SESSION_KEY=abc\n")
out = subprocess.run([sys.executable, os.path.join(M, "make_backup_codes.py")], capture_output=True, text=True).stdout
codes = re.findall(r"^\s+([a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4})$", out, re.M)
check("8 backup codes made", len(codes) == 8)
cfg = open(os.path.join(M, "config.env")).read()
check("config holds hashes only, not the codes", all(c not in cfg for c in codes) and "DASH_BACKUP_CODES=" in cfg)
hashes = re.search(r"DASH_BACKUP_CODES=(.*)", cfg).group(1)
js = os.path.join(T, "t.mjs")
open(js, "w").write('''import * as s from "%s/dashboard/lib/security.js";
const c = %r; const out = [];
out.push("first use: " + s.checkBackup(c[0]));
out.push("second use: " + s.checkBackup(c[0]));
out.push("upper case and no dashes: " + s.checkBackup(c[1].toUpperCase().replace(/-/g, "")));
out.push("wrong code: " + s.checkBackup("aaaa-bbbb-cccc"));
out.push("six digit: " + s.checkBackup("123456"));
out.push("viewer POST: " + s.pathAllowed("viewer", "/api/recovery"));
out.push("operator recovery: " + s.pathAllowed("operator", "/api/recovery"));
out.push("operator governance: " + s.pathAllowed("operator", "/api/admin/chain"));
out.push("admin governance: " + s.pathAllowed("admin", "/api/admin/chain"));
out.push("viewer GET: " + s.pathAllowed("viewer", "/api/live", "GET"));
process.env.DASH_PATH_ROLES = "/api/rollback=admin,/api/recovery=viewer";
out.push("override rollback operator: " + s.pathAllowed("operator", "/api/rollback"));
out.push("override rollback admin: " + s.pathAllowed("admin", "/api/rollback"));
out.push("override recovery viewer: " + s.pathAllowed("viewer", "/api/recovery"));
console.log(out.join("\\n"));
''' % (ROOT, codes))
env = dict(os.environ, DASH_BACKUP_CODES=hashes, DASH_BACKUP_USED=os.path.join(T, "used.txt"), DASH_PATH_ROLES="")
r = subprocess.run(["node", js], capture_output=True, text=True, env=env); o = r.stdout
for want in ("first use: true", "second use: false", "upper case and no dashes: true", "wrong code: false", "six digit: false", "viewer POST: false", "operator recovery: true",
             "operator governance: false", "admin governance: true", "viewer GET: true", "override rollback operator: false", "override rollback admin: true", "override recovery viewer: true"):
    check(want, want in o)
if r.returncode: print(r.stderr[-400:])
# secrets recovery key (the passphrase prompt reads the terminal: use a pty)
def run_pty(args, answers, env2=None):
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(M); os.environ.update(env2 or {}); os.execv(sys.executable, [sys.executable] + args)
    buf = b""; i = 0; t0 = time.time()
    while time.time() - t0 < 60:
        try: d = os.read(fd, 4096)
        except OSError: break
        if not d: break
        buf += d
        if i < len(answers) and (b"passphrase" in buf.lower() or b"again" in buf.lower()) and buf.rstrip().endswith(b":"):
            os.write(fd, (answers[i] + "\n").encode()); i += 1; buf += b"\n"
    os.waitpid(pid, 0); return buf.decode(errors="replace")
sv = os.path.join(M, "secrets_vault.py")
run_pty([sv, "seal"], ["correct horse battery", "correct horse battery"])
check("sealed", os.path.exists(os.path.join(M, "secrets.enc")))
o = run_pty([sv, "recovery-key"], ["correct horse battery"])
rk = re.search(r"(RK-(?:[A-Z2-7]{4}-)+[A-Z2-7]{1,4})", o); check("recovery key printed", bool(rk))
o2 = run_pty([sv, "env"], [rk.group(1) if rk else "x"])
check("recovery key opens the sealed secrets", "DASH_PASS" in o2 and "adminpass123" in o2)
o3 = run_pty([sv, "env"], ["RK-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG"])
check("wrong recovery key refused", "adminpass123" not in o3)
shutil.rmtree(T, ignore_errors=True); sys.exit(1 if bad else 0)
