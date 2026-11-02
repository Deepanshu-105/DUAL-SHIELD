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
        "kill": True, "contain": "dry", "allow": ["10.0.0.2"]}
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
    subprocess.run([sys.executable, "vault.py", "unfreeze"], capture_output=True)
    check("unfreeze", not os.path.exists("data/vault.frozen"))
    shutil.rmtree(tmp, ignore_errors=True)
    print("\nALL PASS" if ok_all else "\nSOME FAILED")
    sys.exit(0 if ok_all else 1)


main()
