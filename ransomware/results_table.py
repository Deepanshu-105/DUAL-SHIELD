#!/usr/bin/env python3
"""Results table for the evaluation: every mock attack -> verdict, detection time, damage reaching the vault, kill, recovery time, bit-for-bit check.
Runs in a throw-away copy (never touches your real vault/sample).   python3 ransomware/results_table.py [--live] [--runs N]
Writes ransomware/results/results_table.md and .csv.  --live also starts the real guard + a real attacker process (kill time)."""
import csv, hashlib, io, json, os, random, shutil, subprocess, sys, tempfile, time, zipfile
HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = "--live" in sys.argv
RUNS = int(sys.argv[sys.argv.index("--runs") + 1]) if "--runs" in sys.argv else 1
OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True)

tmp = tempfile.mkdtemp(prefix="dsres_")
work = os.path.join(tmp, "ransomware")
shutil.copytree(HERE, work, ignore=shutil.ignore_patterns("data", "baseline.json", "__pycache__", "evidence", "results"))
os.makedirs(os.path.join(tmp, "multi"), exist_ok=True)
shutil.copy(os.path.join(HERE, "..", "multi", "shield_os.py"), os.path.join(tmp, "multi"))
os.chdir(work); sys.path.insert(0, work)
import vault, guard as G
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes(b): return Cipher(algorithms.AES(os.urandom(32)), modes.CTR(os.urandom(16))).encryptor().update(b)
def tree(folder):
    return {os.path.relpath(os.path.join(r, f), folder): hashlib.sha256(open(os.path.join(r, f), "rb").read()).hexdigest()
            for r, _, fs in os.walk(folder) for f in fs if not f.startswith(".~ds_")}
def files(): return [os.path.join(r, f) for r, _, fs in os.walk("data/docs") for f in fs]
def note(name="README_DECRYPT.txt", text="All your files are encrypted. Send bitcoin to the wallet below to get the decryptor and your private key. Tor browser: abc.onion\n"):
    open("data/docs/" + name, "w").write(text)

def fresh(n=30):
    for d in ("data", "evidence"): shutil.rmtree(d, ignore_errors=True)
    os.makedirs("data/docs/sub"); os.makedirs("evidence")
    rnd = random.Random(5)
    for i in range(n):
        body = "".join("2026-10-19 12:%02d:%02d host%d svc[%d]: request %d user=u%d status=%d\n" % (rnd.randint(0, 59), rnd.randint(0, 59), i, rnd.randint(100, 999), j, rnd.randint(1, 99), rnd.choice([200, 404, 500])) for j in range(300))
        open("data/docs/%sdoc%d.txt" % ("sub/" if i % 3 == 0 else "", i), "w").write(body)
    cfg = {"roots": [{"name": "docs", "path": "data/docs", "exclude": [], "max_mb": 0}], "debounce_s": 1, "max_wait_s": 5,
           "gate_threshold": 3, "release_after_s": 60, "kill": False, "contain": "dry", "allow": [], "delete_threshold": 10}
    g = G.Guard(dict(G.DEFAULTS, **cfg))
    for r in g.cfg["roots"]: r.setdefault("exclude", []); r.setdefault("max_mb", 0)
    assert g.start()
    return g, tree("data/docs")

# --- attack scenarios: each damages data/docs (the guard watches it); returns after the damage is done
def a_crypto(): 
    for p in files(): b = open(p, "rb").read(); open(p, "wb").write(aes(b)); os.rename(p, p + ".lockbit")
    note("Restore-My-Files.txt")
def a_crypto_hdr():
    for p in files(): b = open(p, "rb").read(); open(p, "wb").write(b[:64] + aes(b[64:]))
def a_crypto_copy():
    for p in files(): b = open(p, "rb").read(); open(p + ".enc7", "wb").write(aes(b)); os.remove(p)
    note("HOW_TO_DECRYPT.txt")
def a_wipe_zero():
    for p in files(): open(p, "wb").write(b"\x00" * os.path.getsize(p))
def a_wipe_trunc():
    for p in files(): open(p, "wb").close()
def a_wipe_del():
    for p in files(): os.remove(p)
def a_double(g):
    src = files()[:10]
    with zipfile.ZipFile("data/docs/stage_all.zip", "w") as z:
        for p in src: z.write(p, os.path.basename(p))
    g.exfil = {"t": time.time(), "rate_mbps": 14.0, "why": "70x its recent normal"}
    for p in [p for p in files() if p.endswith(".txt")]: b = open(p, "rb").read(); open(p, "wb").write(aes(b))
    note("DECRYPT-FILES.txt", "We stole your data. Pay bitcoin or we publish and leak it. decrypt key after payment. wallet below.\n")
def a_exfil(g):
    src = files()[:10]
    with zipfile.ZipFile("data/docs/everything.zip", "w") as z:
        for p in src: z.write(p, os.path.basename(p))
    g.exfil = {"t": time.time(), "rate_mbps": 9.0, "why": "50x its recent normal"}
def a_locker(): note("URGENT.txt", "Your device has been locked until you pay. Unlock your device with the code you receive. bitcoin wallet.\n")
def a_benign():
    for p in files()[:5]: open(p, "a").write("one more line\n")
    open("data/docs/notes.txt", "w").write("remember to buy milk and call the plumber\n")

SCEN = [("Crypto ransomware (LockBit-like, rename + note)", a_crypto, "crypto", True),
        ("Crypto, header kept (evasive)", a_crypto_hdr, "crypto", True),
        ("Crypto, encrypted copy + delete original", a_crypto_copy, "crypto", True),
        ("Wiper, zero-fill", a_wipe_zero, "wiper", True),
        ("Wiper, truncate to 0", a_wipe_trunc, "wiper", True),
        ("Wiper, mass delete", a_wipe_del, "wiper", True),
        ("Double extortion (encrypt + stage archive + note)", a_double, "double_extortion", True),
        ("Data theft only (archive staged)", a_exfil, "exfiltration", False),
        ("Locker / note only", a_locker, "note_only", False),
        ("Benign edits (false-positive check)", a_benign, None, False)]

rows = []
for name, fn, want, damage in SCEN:
    for run in range(RUNS):
        g, clean = fresh()
        fn(g) if fn.__code__.co_argcount else fn()
        t0 = time.perf_counter(); rev = g.gated_commit("t"); det = time.perf_counter() - t0
        v = g.verdict; got = v["primary"] if v else None
        row = {"attack": name, "expected": want or "no alarm", "named": got or "no alarm",
               "correct": "yes" if got == want else "NO", "gate_tripped": "yes" if rev is None else "no",
               "vault_clean": "yes" if (rev is None or not damage) else "NO", "detect_s": round(det, 2),
               "recovered": "n/a", "recover_s": "", "kill": "n/a"}
        if damage:
            t1 = time.perf_counter()
            r = subprocess.run([sys.executable, "recover.py", "docs", "data/docs", "--in-place"], capture_output=True, text=True)
            rec = time.perf_counter() - t1
            ok = r.returncode == 0 and tree("data/docs") == clean
            row.update(recovered="yes, bit-for-bit" if ok else "NO", recover_s=round(rec, 2))
        rows.append(row)

if LIVE:
    ATT = ("import os,sys,time;from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes\n"
           "for r,_,fs in os.walk('data/docs'):\n"
           " for f in fs:\n"
           "  p=os.path.join(r,f);b=open(p,'rb').read();h=open(p,'wb');h.write(Cipher(algorithms.AES(os.urandom(32)),modes.CTR(os.urandom(16))).encryptor().update(b));h.flush();time.sleep(0.4);h.close()\n")
    for label, cmd in (("LIVE crypto process (handle held open)", [sys.executable, "-c", ATT]),
                       ("LIVE wiper process (zero-fill)", [sys.executable, "mock_wiper.py", "zero", "data/docs", "--delay", "0.3"])):
        g, clean = fresh()
        json.dump(dict(g.cfg, kill=True), open("protect.json", "w"))
        log = open("guard_live.log", "w")
        gp = subprocess.Popen([sys.executable, "-u", "guard.py", "protect.json"], stdout=log, stderr=subprocess.STDOUT)
        try:
            t0 = time.time()
            while "GUARD_ON" not in open("guard_live.log").read() and time.time() - t0 < 20: time.sleep(0.2)
            ts = time.perf_counter(); ap = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            killed = None
            while time.perf_counter() - ts < 25:
                if "KILLED pid=" in open("guard_live.log").read(): killed = time.perf_counter() - ts; break
                time.sleep(0.1)
            L = open("guard_live.log").read()
            typ = next((l.split("RANSOM_TYPE", 1)[1].split()[0] for l in L.splitlines() if "RANSOM_TYPE" in l), "")
            typ = typ if typ else "(not logged)"
            time.sleep(1)
            row = {"attack": label, "expected": "killed", "named": typ, "correct": "yes" if killed else "NO",
                   "gate_tripped": "yes" if vault.is_frozen() else "no", "vault_clean": "yes" if vault.is_frozen() else "check",
                   "detect_s": round(killed, 2) if killed else "", "recovered": "", "recover_s": "", "kill": "yes" if killed else "NO"}
            try: ap.kill()
            except Exception: pass
        finally:
            gp.terminate(); gp.wait(5)
        t1 = time.perf_counter()
        r = subprocess.run([sys.executable, "recover.py", "docs", "data/docs", "--in-place"], capture_output=True, text=True)
        ok = r.returncode == 0 and tree("data/docs") == clean
        row.update(recovered="yes, bit-for-bit" if ok else "NO", recover_s=round(time.perf_counter() - t1, 2))
        rows.append(row)

cols = ["attack", "expected", "named", "correct", "gate_tripped", "vault_clean", "detect_s", "kill", "recovered", "recover_s"]
with open(os.path.join(OUT, "results_table.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(rows)
md = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n" + "".join("| " + " | ".join(str(r[c]) for c in cols) + " |\n" for r in rows)
bad = [r for r in rows if r["correct"] != "yes" or r["vault_clean"] == "NO" or r["recovered"] == "NO"]
md += "\n%d scenarios, %d problems. detect_s = time from end of attack to verdict (live rows: time to kill). Run on: %s\n" % (len(rows), len(bad), sys.platform)
open(os.path.join(OUT, "results_table.md"), "w").write(md)
print(md); print("saved:", OUT)
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(1 if bad else 0)
