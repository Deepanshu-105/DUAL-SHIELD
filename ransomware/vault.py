"""Git-backed snapshot vault: incremental, deduplicated, off-machine.

    python3 vault.py init    data/sample
    python3 vault.py commit  data/sample
    python3 vault.py push
    python3 vault.py restore data/sample_copy
    python3 vault.py restore data/sample_copy --rev HEAD~3
    python3 vault.py log

Extensions (steps 5-7):
    python3 vault.py status              frozen? last commit? roots?
    python3 vault.py freeze  [--reason]  stop all commits (set by containment)
    python3 vault.py unfreeze            allow commits again (after restore)
    python3 vault.py restore data/out --root docs     restore one named root
Continuous, gated, multi-root protection lives in guard.py (uses these helpers).
"""
import argparse, hashlib, json, os, shutil, subprocess, sys, time

VAULT = "data/vault"


def sh(*args, cwd=VAULT, check=True):
    return subprocess.run(args, cwd=cwd, check=check,
                           capture_output=True, text=True)


def init(folder, remote=None):
    os.makedirs(VAULT, exist_ok=True)
    if not os.path.isdir(os.path.join(VAULT, ".git")):
        sh("git", "init", "-q")
        sh("git", "config", "user.email", "vault@dual-shield.local")
        sh("git", "config", "user.name", "Dual-Shield Vault")
    if remote:
        existing = sh("git", "remote", check=False).stdout.split()
        if "origin" not in existing:
            sh("git", "remote", "add", "origin", remote)
    with open(os.path.join(VAULT, ".meta.json"), "w") as f:
        json.dump({"source": os.path.abspath(folder)}, f)
    print("VAULT_INIT", VAULT, "source:", folder)


LOCK = VAULT + ".frozen"          # outside the git tree, so it is never committed


def is_frozen():
    return os.path.exists(LOCK)


def freeze(reason="manual"):
    os.makedirs(os.path.dirname(LOCK) or ".", exist_ok=True)
    with open(LOCK, "w") as f:
        json.dump({"since": time.time(), "reason": reason}, f)
    print("VAULT_FROZEN", reason, flush=True)


def unfreeze():
    if os.path.exists(LOCK):
        os.remove(LOCK)
        print("VAULT_UNFROZEN")
    else:
        print("VAULT_NOT_FROZEN")


def _ignore(exclude=(), max_bytes=0):
    """shutil.copytree ignore callback: skip patterns and files over max_bytes."""
    import fnmatch

    def fn(d, names):
        out = []
        for n in names:
            p = os.path.join(d, n)
            if any(fnmatch.fnmatch(n, pat) for pat in exclude):
                out.append(n)
            elif max_bytes and os.path.isfile(p) and os.path.getsize(p) > max_bytes:
                out.append(n)
        return out
    return fn


def _swap_in(stage):
    dest = os.path.join(VAULT, "files")
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.move(stage, dest)


def _commit_staged(label, t0):
    sh("git", "add", "-A")
    diff = sh("git", "diff", "--cached", "--stat", check=False)
    if not diff.stdout.strip():
        print("VAULT_NOOP no changes since last snapshot")
        return None
    msg = "snapshot %s%s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                              (" " + label) if label else "")
    sh("git", "commit", "-q", "-m", msg)
    rev = sh("git", "rev-parse", "--short", "HEAD").stdout.strip()
    ms = (time.perf_counter() - t0) * 1000
    print("VAULT_COMMIT rev=%s %.0f ms" % (rev, ms), flush=True)
    return rev


def commit(folder, label=""):
    """Legacy single-folder commit (layout: files/<contents>)."""
    if is_frozen():
        print("VAULT_REFUSED vault is frozen (attack suspected); run: vault.py unfreeze")
        return None
    t0 = time.perf_counter()
    stage = VAULT + ".stage"
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(folder, stage)
    _swap_in(stage)
    return _commit_staged(label, t0)


def commit_roots(roots, label="", hold=None):
    """Multi-root commit (layout: files/<name>/...).

    roots: list of {"name","path","exclude","max_mb"}.
    hold:  {name: set(rel paths)} - files NOT to update this time; their previous
           vault version is kept (or omitted if they are new), so a half-encrypted
           file can never overwrite a clean copy.
    """
    if is_frozen():
        print("VAULT_REFUSED vault is frozen (attack suspected)", flush=True)
        return None
    hold = hold or {}
    t0 = time.perf_counter()
    stage = VAULT + ".stage"
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage)
    old = os.path.join(VAULT, "files")
    for r in roots:
        if not os.path.isdir(r["path"]):
            print("VAULT_SKIP_ROOT missing:", r["path"])
            continue
        out = os.path.join(stage, r["name"])
        shutil.copytree(r["path"], out, symlinks=True,
                        ignore=_ignore(r.get("exclude", ()), int(r.get("max_mb", 0)) * 1048576))
        for rel in hold.get(r["name"], ()):
            keep = os.path.join(old, r["name"], rel)
            dst = os.path.join(out, rel)
            if os.path.exists(keep):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(keep, dst)
            elif os.path.exists(dst):
                os.remove(dst)
    _swap_in(stage)
    with open(os.path.join(VAULT, ".meta.json"), "w") as f:
        json.dump({"roots": [{"name": r["name"], "path": os.path.abspath(r["path"])} for r in roots]}, f)
    return _commit_staged(label, t0)


def status():
    info = {"frozen": is_frozen(), "vault": os.path.isdir(os.path.join(VAULT, ".git"))}
    if info["frozen"]:
        info["freeze"] = json.load(open(LOCK))
    if info["vault"]:
        r = sh("git", "log", "--oneline", "-1", check=False).stdout.strip()
        info["last_commit"] = r or None
        info["commits"] = len(sh("git", "log", "--oneline", check=False).stdout.splitlines())
        mp = os.path.join(VAULT, ".meta.json")
        if os.path.exists(mp):
            info["meta"] = json.load(open(mp))
    print(json.dumps(info, indent=2))
    return info


def push():
    r = sh("git", "push", "origin", "HEAD:main", check=False)
    if r.returncode == 0:
        print("VAULT_PUSHED (off-machine copy updated)")
    else:
        print("VAULT_PUSH_FAILED", r.stderr.strip()[:200])


def restore(target, rev="HEAD", root=None):
    t0 = time.perf_counter()
    import tarfile, io
    sub = "files/" + root if root else "files"
    proc = subprocess.run(["git", "archive", rev, sub], cwd=VAULT,
                           capture_output=True)
    if proc.returncode != 0:
        print("VAULT_RESTORE_FAIL", "revision not found:", rev)
        return False
    os.makedirs(target, exist_ok=True)
    tar = tarfile.open(fileobj=io.BytesIO(proc.stdout))
    tar.extractall(target)
    inner = os.path.join(target, sub)
    if os.path.isdir(inner):
        for name in os.listdir(inner):
            shutil.move(os.path.join(inner, name), os.path.join(target, name))
        shutil.rmtree(os.path.join(target, "files"), ignore_errors=True)
    ms = (time.perf_counter() - t0) * 1000
    print("VAULT_RESTORED rev=%s -> %s, %.0f ms" % (rev, target, ms))
    return True


def log():
    r = sh("git", "log", "--oneline", "-20", check=False)
    print(r.stdout or "VAULT_EMPTY no snapshots yet")


def prune(keep=20):
    count = len(sh("git", "log", "--oneline").stdout.splitlines())
    if count <= keep:
        print("VAULT_PRUNE_SKIP", count, "commits, under limit")
        return
    base = sh("git", "rev-list", "HEAD", "--max-count=1",
               "--skip=%d" % keep).stdout.strip()
    sh("git", "checkout", "--orphan", "tmp_squash", base, check=False)
    sh("git", "commit", "-q", "-m", "squashed history before %s" % base[:7])
    print("VAULT_PRUNED kept newest", keep, "commits")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["init", "commit", "push", "restore", "log", "prune", "status", "freeze", "unfreeze"])
    ap.add_argument("folder", nargs="?")
    ap.add_argument("--remote")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--label", default="")
    ap.add_argument("--root")
    ap.add_argument("--reason", default="manual")
    a = ap.parse_args()
    if a.cmd == "init":
        init(a.folder, a.remote)
    elif a.cmd == "commit":
        commit(a.folder, a.label)
    elif a.cmd == "push":
        push()
    elif a.cmd == "restore":
        sys.exit(0 if restore(a.folder, a.rev, a.root) else 1)
    elif a.cmd == "log":
        log()
    elif a.cmd == "prune":
        prune()
    elif a.cmd == "status":
        status()
    elif a.cmd == "freeze":
        freeze(a.reason)
    elif a.cmd == "unfreeze":
        unfreeze()
