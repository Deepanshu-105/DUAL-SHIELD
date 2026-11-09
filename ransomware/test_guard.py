"""End-to-end test of steps 5-7. Run from ransomware/:  python3 test_guard.py
Works in a throw-away copy of this folder, so it never touches your real vault/data."""
import hashlib, json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ok_all = True


def check(name, cond, extra=""):
    global ok_all
    ok_all &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (("  " + str(extra)) if extra else ""))


def tree_hash(folder):
    h = {}
    for r, _, fs in os.walk(folder):
        for f in fs:
            p = os.path.join(r, f)
            h[os.path.relpath(p, folder)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return h


def wait_for(path_or_fn, secs):
    t = time.time()
    while time.time() - t < secs:
        if path_or_fn():
            return True
        time.sleep(0.1)
    return False


def make_sample():
    """Own sample data (10 files), so the test also works on branches without setup_sample.sh."""
    import random, zipfile
    random.seed(7)
    os.makedirs("data/sample", exist_ok=True)
    for i in range(1, 7):
        text, n = "", 0
        while len(text) < 12801:
            n += 1
            text += "2026-10-19 15:02:%02d host%d app[%d]: event %d user=u%d\n" % (n % 60, i, 1000 + i, n, random.randint(1, 99))
        open("data/sample/log%d.txt" % i, "w").write(text[:12801])
    for i in range(1, 4):
        open("data/sample/random%d.bin" % i, "wb").write(random.randbytes(20000))
    with zipfile.ZipFile("data/sample/archive.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("notes.txt", "dual-shield demo archive\n" * 20)
    shutil.copytree("data/sample", "data/sample_copy", dirs_exist_ok=True)


def main():
    tmp = tempfile.mkdtemp(prefix="dsguard_")
    work = os.path.join(tmp, "ransomware")
    shutil.copytree(HERE, work, ignore=shutil.ignore_patterns("data", "baseline.json", "__pycache__", "evidence"))
    os.makedirs(os.path.join(tmp, "multi"), exist_ok=True); shutil.copy(os.path.join(os.path.join(HERE, ".."), "multi", "shield_os.py"), os.path.join(tmp, "multi"))   # v10: the OS layer sits next to ransomware/
    os.chdir(work)
    make_sample()
    # step 7: two roots, one extra root with excluded and oversized files
    docs = os.path.join(work, "data", "docs")
    os.makedirs(docs)
    open(os.path.join(docs, "a.txt"), "w").write("hello docs\n" * 400)
    open(os.path.join(docs, "skip.tmp"), "w").write("temp")
    open(os.path.join(docs, "big.bin"), "wb").write(os.urandom(2 * 1048576))
    cfg = {"roots": [
        {"name": "sample", "path": "data/sample_copy", "exclude": ["*.tmp"], "max_mb": 1},
        {"name": "docs", "path": "data/docs", "exclude": ["*.tmp"], "max_mb": 1}],
        "debounce_s": 1, "max_wait_s": 10, "gate_threshold": 3, "release_after_s": 60,
        "kill": True, "contain": "dry", "allow": ["10.0.0.2"],
        "remote": os.path.join(tmp, "offsite.git"), "encrypt": True}
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", cfg["remote"]], check=True)
    for k in ("receive.denyNonFastForwards", "receive.denyDeletes"):          # what multi/make_vault_remote.sh sets
        subprocess.run(["git", "--git-dir", cfg["remote"], "config", k, "true"], check=True)
    json.dump(cfg, open("protect.json", "w"))
    clean = tree_hash("data/sample")

    log = open("guard.log", "w")
    g = subprocess.Popen([sys.executable, "-u", "guard.py", "protect.json"], stdout=log, stderr=subprocess.STDOUT)
    try:
        check("guard started", wait_for(lambda: "GUARD_ON" in open("guard.log").read(), 15))
        ls = subprocess.run(["git", "ls-files"], cwd="data/vault", capture_output=True, text=True).stdout
        check("step7 both roots in vault", "files/sample/log1.txt" in ls and "files/docs/a.txt" in ls)
        check("step7 exclude + size cap honoured", "skip.tmp" not in ls and "big.bin" not in ls)

        # step 5: a normal edit is committed within ~debounce seconds
        n0 = len(subprocess.run(["git", "log", "--oneline"], cwd="data/vault", capture_output=True, text=True).stdout.splitlines())
        t0 = time.time()
        with open("data/docs/a.txt", "a") as f:
            f.write("new line added by the user\n")
        got = wait_for(lambda: len(subprocess.run(["git", "log", "--oneline"], cwd="data/vault", capture_output=True, text=True).stdout.splitlines()) > n0, 8)
        check("step5 edit auto-committed", got, "%.1fs after the edit" % (time.time() - t0))
        check("step5 loss window small (<4s)", got and time.time() - t0 < 4)

        # attack
        subprocess.Popen([sys.executable, "mock_crypto.py", "--delay", "0.05"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check("kill rule fired", wait_for(lambda: "KILLED pid=" in open("guard.log").read(), 10))
        check("step6 CONTAINED printed", wait_for(lambda: "CONTAINED" in open("guard.log").read(), 5))
        check("step6 vault frozen", os.path.exists("data/vault.frozen"))
        ev = json.load(open("evidence/containment.json")) if os.path.exists("evidence/containment.json") else {}
        check("step6 evidence written", ev.get("mode") == "dry" and ev.get("allow") == ["10.0.0.2"])
        check("step6 quarantine commands (dry)", "CONTAIN_DRY_RUN iptables -I OUTPUT 1 -j DS_QUAR" in open("guard.log").read())
        time.sleep(3)   # debounce passes; nothing may be committed while frozen
        out = subprocess.run([sys.executable, "vault.py", "commit", "data/sample_copy"], capture_output=True, text=True).stdout
        check("frozen vault refuses commit", "VAULT_REFUSED" in out)
    finally:
        g.terminate()
        g.wait(5)

    # restore from vault = original data, bit for bit
    shutil.rmtree("data/restored", ignore_errors=True)
    subprocess.run([sys.executable, "vault.py", "restore", "data/restored", "--root", "sample"], capture_output=True)
    check("restore identical to clean data (no ransom, no loss)", tree_hash("data/restored") == clean)
    # off-machine copy, verification, tamper-skipping recovery
    rl = subprocess.run(["git", "--git-dir", cfg["remote"], "log", "--oneline", "main"], capture_output=True, text=True).stdout
    check("off-machine copy received commits", len(rl.splitlines()) >= 2, "%d commits offsite" % len(rl.splitlines()))
    check("vault verify (Merkle manifest)", subprocess.run([sys.executable, "vault.py", "verify"], capture_output=True).returncode == 0)
    check("vault fsck", subprocess.run([sys.executable, "vault.py", "fsck"], capture_output=True).returncode == 0)
    sm = json.loads(subprocess.run([sys.executable, "vault.py", "summary"], capture_output=True, text=True).stdout)
    check("summary for dashboard", sm["frozen"] and sm["commits"] >= 2 and sm["push"] and sm["push"]["ok"])
    open("data/vault/files/sample/log1.txt", "w").write("TAMPERED")        # someone edits the vault itself
    subprocess.run("git add -A && git -c user.email=x@y -c user.name=x commit -qm tampered", shell=True, cwd="data/vault")
    check("tampered vault commit detected", subprocess.run([sys.executable, "vault.py", "verify"], capture_output=True).returncode == 1)
    rc = subprocess.run([sys.executable, "recover.py", "sample", "data/sample_copy", "--in-place"], capture_output=True, text=True)
    check("recover.py skips tampered commit", rc.returncode == 0 and "RECOVER_SKIP" in rc.stdout and "RECOVER_OK" in rc.stdout, rc.stdout.strip().splitlines()[-1] if rc.stdout else rc.stderr[-200:])
    check("recovered folder identical to clean data", tree_hash("data/sample_copy") == clean)
    check("encrypted folder kept as evidence", any(n.startswith("sample_copy.encrypted-") for n in os.listdir("data")))
    check("recovery report written", json.load(open("evidence/recovery_report.json"))["ok"])
    # encryption at rest + append-only remote
    blob = subprocess.run(["git", "--git-dir", cfg["remote"], "show", "main:files/sample/log1.txt"], capture_output=True).stdout
    check("remote holds ciphertext, not plain text", blob.startswith(b"DSV1") and b"event" not in blob and b"host1" not in blob)
    check("local vault object is encrypted too", subprocess.run("git cat-file -p HEAD~1:files/sample/log1.txt | head -c 4", shell=True, cwd="data/vault", capture_output=True).stdout == b"DSV1")
    sm = json.loads(subprocess.run([sys.executable, "vault.py", "summary"], capture_output=True, text=True).stdout)
    check("summary reports encryption", sm.get("encrypted") is True)
    # disaster recovery on a fresh machine: clone the remote (no git config, no filter), key from the backup
    open("other.key", "w").write("00" * 31 + "aa\n")
    subprocess.run("rm -rf data/vault && git clone -q -b main %s data/vault" % cfg["remote"], shell=True)
    bad = subprocess.run([sys.executable, "vault.py", "restore", "data/wrongkey", "--root", "sample"], capture_output=True, text=True, env=dict(os.environ, VAULT_KEY_FILE="other.key"))
    check("wrong key cannot restore (fails closed)", bad.returncode != 0 and not os.path.isdir("data/wrongkey/files"), bad.stdout.strip()[-70:])
    good = subprocess.run([sys.executable, "vault.py", "restore", "data/fromremote", "--root", "sample"], capture_output=True, text=True)
    check("fresh clone + key backup restores the clean data", good.returncode == 0 and tree_hash("data/fromremote") == clean, good.stdout.strip()[-60:])
    check("vault verify works on the fresh clone", subprocess.run([sys.executable, "vault.py", "verify"], capture_output=True).returncode == 0)
    subprocess.run([sys.executable, "vault.py", "unfreeze"], capture_output=True)
    before = subprocess.run(["git", "--git-dir", cfg["remote"], "rev-list", "--count", "main"], capture_output=True, text=True).stdout.strip()
    subprocess.run("rm -rf data/vault data/vault.push.json", shell=True)                    # someone starts a fresh, unrelated vault
    subprocess.run([sys.executable, "vault.py", "init", "data/sample", "--remote", cfg["remote"]], capture_output=True)
    subprocess.run([sys.executable, "vault.py", "commit", "data/sample"], capture_output=True)
    subprocess.run([sys.executable, "vault.py", "push"], capture_output=True)
    after = subprocess.run(["git", "--git-dir", cfg["remote"], "rev-list", "--count", "main"], capture_output=True, text=True).stdout.strip()
    branches = subprocess.run(["git", "--git-dir", cfg["remote"], "branch", "--list"], capture_output=True, text=True).stdout
    check("push never overwrites: old history intact, new data on a new branch", before == after and "vault-" in branches, branches.split())
    subprocess.run([sys.executable, "vault.py", "unfreeze"], capture_output=True)
    check("unfreeze", not os.path.exists("data/vault.frozen"))
    shutil.rmtree(tmp, ignore_errors=True)
    print("\nALL PASS" if ok_all else "\nSOME FAILED")
    sys.exit(0 if ok_all else 1)


main()
