"""Git-backed snapshot vault: incremental, deduplicated, off-machine.

    python3 vault.py init    data/sample
    python3 vault.py commit  data/sample
    python3 vault.py push
    python3 vault.py restore data/sample_copy
    python3 vault.py restore data/sample_copy --rev HEAD~3
    python3 vault.py log
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


def _copy_in(folder):
    dest = os.path.join(VAULT, "files")
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.copytree(folder, dest)


def commit(folder, label=""):
    t0 = time.perf_counter()
    _copy_in(folder)
    sh("git", "add", "-A")
    diff = sh("git", "diff", "--cached", "--stat", check=False)
    if not diff.stdout.strip():
        print("VAULT_NOOP no changes since last snapshot")
        return
    msg = "snapshot %s%s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                              (" " + label) if label else "")
    sh("git", "commit", "-q", "-m", msg)
    rev = sh("git", "rev-parse", "--short", "HEAD").stdout.strip()
    ms = (time.perf_counter() - t0) * 1000
    print("VAULT_COMMIT rev=%s %.0f ms" % (rev, ms))


def push():
    r = sh("git", "push", "origin", "HEAD:main", check=False)
    if r.returncode == 0:
        print("VAULT_PUSHED (off-machine copy updated)")
    else:
        print("VAULT_PUSH_FAILED", r.stderr.strip()[:200])


def restore(target, rev="HEAD"):
    t0 = time.perf_counter()
    import tarfile, io
    proc = subprocess.run(["git", "archive", rev, "files"], cwd=VAULT,
                           capture_output=True)
    if proc.returncode != 0:
        print("VAULT_RESTORE_FAIL", "revision not found:", rev)
        return False
    os.makedirs(target, exist_ok=True)
    tar = tarfile.open(fileobj=io.BytesIO(proc.stdout))
    tar.extractall(target)
    inner = os.path.join(target, "files")
    if os.path.isdir(inner):
        for name in os.listdir(inner):
            shutil.move(os.path.join(inner, name), os.path.join(target, name))
        os.rmdir(inner)
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
    ap.add_argument("cmd", choices=["init", "commit", "push", "restore", "log", "prune"])
    ap.add_argument("folder", nargs="?")
    ap.add_argument("--remote")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    if a.cmd == "init":
        init(a.folder, a.remote)
    elif a.cmd == "commit":
        commit(a.folder, a.label)
    elif a.cmd == "push":
        push()
    elif a.cmd == "restore":
        sys.exit(0 if restore(a.folder, a.rev) else 1)
    elif a.cmd == "log":
        log()
    elif a.cmd == "prune":
        prune()
