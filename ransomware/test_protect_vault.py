#!/usr/bin/env python3
"""Linux, run as root: after `lock`, an ordinary account (nobody) cannot read, change, delete or add anything in the vault; the owner (guard) still can."""
import os, subprocess, sys, tempfile, shutil
if os.name == "nt" or os.geteuid() != 0: print("SKIP (Linux + root needed)"); sys.exit(0)
HERE = os.path.dirname(os.path.abspath(__file__)); bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
d = tempfile.mkdtemp(); os.chmod(d, 0o777)
v = os.path.join(d, "vault"); subprocess.run(["git", "init", "-q", v], check=True)
open(os.path.join(v, "snap.txt"), "w").write("clean"); subprocess.run(["git", "-C", v, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"]); subprocess.run(["git", "-C", v, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "s"])
subprocess.run(["chmod", "-R", "a+rwX", v]); key = os.path.join(d, "vault.key"); open(key, "w").write("k"); os.chmod(key, 0o666)
env = dict(os.environ, VAULT_DIR=v, VAULT_KEY=key)
P = [sys.executable, os.path.join(HERE, "protect_vault.py")]
def as_nobody(code):
    return subprocess.run([sys.executable, "-c", "import os;os.setgid(65534);os.setuid(65534)\n" + code], capture_output=True, text=True).returncode
W = "import os,shutil;p=%r;\ntry:\n open(p+'/.git/HEAD','a').write('x');print('WROTE')\nexcept Exception: pass\ntry:\n shutil.rmtree(p);print('DELETED')\nexcept Exception: pass" % v
r = subprocess.run(P + ["status"], env=env, capture_output=True, text=True); check("before lock: EXPOSED", "VAULT_EXPOSED" in r.stdout)
MV = "import os;os.setgid(65534);os.setuid(65534)\ntry:\n os.rename(%r,%r);print('MOVED')\nexcept Exception:\n print('DENIED')"
r = subprocess.run([sys.executable, "-c", MV % (v, v + "_gone")], capture_output=True, text=True)
check("before lock: an ordinary account CAN move the vault away (the problem)", "MOVED" in r.stdout)
shutil.rmtree(d); d = tempfile.mkdtemp(); os.chmod(d, 0o777)    # rebuild
v = os.path.join(d, "vault"); subprocess.run(["git", "init", "-q", v], check=True)
open(os.path.join(v, "snap.txt"), "w").write("clean"); subprocess.run(["git", "-C", v, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"]); subprocess.run(["git", "-C", v, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "s"])
key = os.path.join(d, "vault.key"); open(key, "w").write("k"); subprocess.run(["chmod", "-R", "a+rwX", v]); os.chmod(key, 0o666)
env = dict(os.environ, VAULT_DIR=v, VAULT_KEY=key)
r = subprocess.run(P + ["lock"], env=env, capture_output=True, text=True); check("lock runs", "VAULT_LOCKED" in r.stdout and "VAULT_PROTECTED" in r.stdout)
check("nobody cannot list the vault", subprocess.run([sys.executable, "-c", "import os;os.setgid(65534);os.setuid(65534);os.listdir(%r)" % v], capture_output=True).returncode != 0)
r = subprocess.run([sys.executable, "-c", "import os,shutil;os.setgid(65534);os.setuid(65534)\ntry:\n shutil.rmtree(%r);print('DELETED')\nexcept Exception:\n print('DENIED')" % v], capture_output=True, text=True)
check("nobody cannot delete it", "DENIED" in r.stdout and os.path.isdir(v))
r = subprocess.run([sys.executable, "-c", MV % (v, v + "_gone")], capture_output=True, text=True)
check("nobody cannot move it away (sticky parent)", "DENIED" in r.stdout and os.path.isdir(v))
r = subprocess.run([sys.executable, "-c", "import os;os.setgid(65534);os.setuid(65534)\ntry:\n open(%r,'w').write('x');print('WROTE')\nexcept Exception:\n print('DENIED')" % key], capture_output=True, text=True)
check("nobody cannot overwrite the key", "DENIED" in r.stdout)
check("the owner (guard, root) can still commit", subprocess.run(["git", "-C", v, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-qm", "again"]).returncode == 0)
r = subprocess.run(P + ["selfcheck"], env=env, capture_output=True, text=True); check("selfcheck: fsck ok, no remote reported", "VAULT_FSCK_OK" in r.stdout and "VAULT_NO_REMOTE" in r.stdout)
shutil.rmtree(d); sys.exit(1 if bad else 0)
