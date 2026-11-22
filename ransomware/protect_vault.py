#!/usr/bin/env python3
"""Protect the vault from the malware it is meant to survive (v13.8).
   Linux (run as root):   sudo python3 ransomware/protect_vault.py lock      # vault + key owned by root, mode 700: other accounts cannot read, change or delete them
   Windows (Administrator): python ransomware\\protect_vault.py lock          # ACL: only SYSTEM and Administrators (icacls)
   python3 ransomware/protect_vault.py status | selfcheck | unlock
 Run the guard as that privileged account (service); a ransomware that runs as the ordinary user then cannot touch the vault.
 It does NOT help if the malware gets root/Administrator: use the append-only remote (multi/make_vault_remote.sh) as well.
 selfcheck = git fsck of the vault + (if a remote is configured) the remote contains every local snapshot."""
import json, os, stat, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WIN = os.name == "nt"
def paths():
    v = os.environ.get("VAULT_DIR") or os.path.join(HERE, "data", "vault")
    k = os.environ.get("VAULT_KEY") or os.path.join(HERE, "data", "vault.key")
    return [p for p in (v, k) if os.path.exists(p)]
def run(*a): return subprocess.run(a, capture_output=True, text=True)

def lock():
    ps = paths()
    if not ps: sys.exit("no vault found (run the guard once first)")
    if WIN:
        for p in ps:
            r = run("icacls", p, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C")
            if r.returncode: sys.exit("icacls failed: " + (r.stdout + r.stderr)[-300:])
    else:
        if os.geteuid() != 0: sys.exit("run as root: sudo python3 %s lock" % sys.argv[0])
        for p in ps:
            run("chown", "-R", "root:root", p)
            run("chmod", "-R", "go-rwx", p)
            par = os.path.dirname(os.path.abspath(p))
            run("chmod", "o+t", par)       # sticky bit: in a folder the user can write to, only the owner (root) may rename or delete the vault itself
    print("VAULT_LOCKED", ", ".join(ps)); status()

def unlock():
    for p in paths():
        if WIN: run("icacls", p, "/reset", "/T", "/C")
        else: run("chmod", "-R", "u+rwX", p)
    print("VAULT_UNLOCKED (accounts other than the owner are still not granted anything on Linux; chown it back if the guard runs as another user)")

def unsafe_linux(p):
    bad = []
    for root, ds, fs in os.walk(p):
        for n in ds + fs:
            try: st = os.lstat(os.path.join(root, n))
            except OSError: continue
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IROTH): bad.append(os.path.join(root, n))
            if len(bad) > 3: return bad
    return bad

def status(quiet=False):
    ok, notes = True, []
    ps = paths()
    if not ps: notes.append("no vault yet"); ok = False
    for p in ps:
        if WIN:
            out = run("icacls", p).stdout
            if any(w in out for w in ("Everyone", "BUILTIN\\Users", "Authenticated Users")): ok = False; notes.append("%s: ordinary users have access" % p)
        else:
            st = os.stat(p)
            if st.st_uid != 0: ok = False; notes.append("%s: owned by uid %d, not root" % (p, st.st_uid))
            b = unsafe_linux(p)
            if b: ok = False; notes.append("%s: group/other can access (%s ...)" % (p, b[0]))
    if not WIN and os.geteuid() != 0: notes.append("this process is not root: the guard itself runs with the same rights as ordinary programs")
    if not quiet: print(("VAULT_PROTECTED" if ok else "VAULT_EXPOSED") + ("  - " + "; ".join(notes) if notes else ""))
    return ok, notes

def selfcheck():
    v = paths()[0] if paths() else None
    if not v or not os.path.isdir(os.path.join(v, ".git")): sys.exit("VAULT_MISSING")
    git = ["git", "--git-dir", os.path.join(v, ".git")]
    r = run(*git, "fsck", "--no-dangling")
    if r.returncode: print("VAULT_CORRUPT", (r.stdout + r.stderr)[-300:]); sys.exit(2)
    n = run(*git, "rev-list", "--all", "--count").stdout.strip()
    print("VAULT_FSCK_OK snapshots=%s" % n)
    rem = run(*git, "config", "--get", "remote.origin.url").stdout.strip()
    if not rem: print("VAULT_NO_REMOTE (no off-machine copy)"); return
    ls = run(*git, "ls-remote", "--heads", "origin")
    if ls.returncode: print("VAULT_REMOTE_UNREACHABLE", ls.stderr[-200:]); sys.exit(3)
    run(*git, "fetch", "-q", "origin"); head = run(*git, "rev-parse", "HEAD").stdout.strip()
    held = any(run(*git, "merge-base", "--is-ancestor", head, ln.split()[0]).returncode == 0 for ln in ls.stdout.splitlines() if ln.strip())
    print("VAULT_REMOTE_HAS_HEAD" if held else "VAULT_REMOTE_BEHIND (last snapshot not yet on the remote)")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    {"lock": lock, "unlock": unlock, "status": status, "selfcheck": selfcheck}.get(cmd, lambda: sys.exit(__doc__))()
