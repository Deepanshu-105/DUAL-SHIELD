"""Attack-type tests: for each kind of ransomware, does Dual-Shield name it, stop the damage reaching the vault, and recover?
Run from anywhere:  python3 ransomware/test_types.py     (works in a throw-away copy; needs `cryptography`)"""
import hashlib, io, json, os, random, shutil, subprocess, sys, tempfile, time, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ok_all = True
def check(name, cond, extra=""):
    global ok_all
    ok_all &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (("  " + str(extra)) if extra else ""))

tmp = tempfile.mkdtemp(prefix="dstypes_")
work = os.path.join(tmp, "ransomware")
shutil.copytree(HERE, work, ignore=shutil.ignore_patterns("data", "baseline.json", "__pycache__", "evidence"))
os.makedirs(os.path.join(tmp, "multi"), exist_ok=True); shutil.copy(os.path.join(os.path.join(HERE, ".."), "multi", "shield_os.py"), os.path.join(tmp, "multi"))   # v10: the OS layer sits next to ransomware/
os.chdir(work); sys.path.insert(0, work)
import classify, detect, vault, containment, guard as G
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes(b):
    return Cipher(algorithms.AES(os.urandom(32)), modes.CTR(os.urandom(16))).encryptor().update(b)

def tree(folder):
    return {os.path.relpath(os.path.join(r, f), folder): hashlib.sha256(open(os.path.join(r, f), "rb").read()).hexdigest()
            for r, _, fs in os.walk(folder) for f in fs if not f.startswith(".~ds_")}

def fresh(n=30):
    for d in ("data", "evidence"):
        shutil.rmtree(d, ignore_errors=True)
    os.makedirs("data/docs/sub"); os.makedirs("evidence")
    rnd = random.Random(5)
    for i in range(n):
        body = "".join("2026-10-19 12:%02d:%02d host%d svc[%d]: request %d user=u%d status=%d\n" % (rnd.randint(0, 59), rnd.randint(0, 59), i, rnd.randint(100, 999), j, rnd.randint(1, 99), rnd.choice([200, 404, 500])) for j in range(300))
        open("data/docs/%sdoc%d.txt" % ("sub/" if i % 3 == 0 else "", i), "w").write(body)
    cfg = {"roots": [{"name": "docs", "path": "data/docs", "exclude": [], "max_mb": 0}], "debounce_s": 1, "max_wait_s": 5,
           "gate_threshold": 3, "release_after_s": 60, "kill": False, "contain": "dry", "allow": [], "delete_threshold": 10}
    g = G.Guard(dict(G.DEFAULTS, **cfg))
    for r in g.cfg["roots"]:
        r.setdefault("exclude", []); r.setdefault("max_mb", 0)
    assert g.start()
    return g, tree("data/docs")

def files():
    return [os.path.join(r, f) for r, _, fs in os.walk("data/docs") for f in fs]

def run(g):
    rev = g.gated_commit("t")
    return rev, g.verdict

def note(name="README_DECRYPT.txt", text="All your files are encrypted. Send bitcoin to the wallet below to get the decryptor and your private key. Tor browser: abc.onion\n"):
    open("data/docs/" + name, "w").write(text)

def recover_ok(clean):
    r = subprocess.run([sys.executable, "recover.py", "docs", "data/docs", "--in-place"], capture_output=True, text=True)
    return r.returncode == 0 and tree("data/docs") == clean, r.stdout[-200:]

def types(v):
    return [t["type"] for t in (v or {}).get("types", [])]

# ---------------------------------------------------------------- 1 crypto, in place, header overwritten, note + rename
g, clean = fresh()
for p in files():
    b = open(p, "rb").read(); open(p, "wb").write(aes(b)); os.rename(p, p + ".lockbit")
note("Restore-My-Files.txt")
rev, v = run(g)
check("crypto: named", v and v["primary"] == "crypto" and v["types"][0]["confidence"] == "high", v and v["types"])
check("crypto: extension and family hint", v and v["extension"] == ".lockbit" and v["family_hint"] == "LockBit-like", v and (v["extension"], v["family_hint"]))
check("crypto: gate tripped, nothing bad committed, vault frozen", rev is None and vault.is_frozen())
ok, out = recover_ok(clean); check("crypto: recovered bit for bit", ok, out)
check("crypto: evidence written for the dashboard", json.load(open("evidence/ransom_class.json"))["primary"] == "crypto")

# ---------------------------------------------------------------- 2 crypto, header kept (evasive)
g, clean = fresh()
for p in files():
    b = open(p, "rb").read(); open(p, "wb").write(b[:64] + aes(b[64:]))
rev, v = run(g)
check("crypto (header kept): named with the evasive mode", v and v["primary"] == "crypto" and "header kept" in (v["mode"] or ""), v and v["mode"])
ok, out = recover_ok(clean); check("crypto (header kept): recovered", ok, out)

# ---------------------------------------------------------------- 3 crypto that writes encrypted copies and deletes the originals
g, clean = fresh()
for p in files():
    b = open(p, "rb").read(); open(p + ".enc7", "wb").write(aes(b)); os.remove(p)
note("HOW_TO_DECRYPT.txt")
rev, v = run(g)
check("crypto (copy + delete): named crypto, not wiper", v and v["primary"] == "crypto" and "wiper" not in types(v), v and types(v))
check("crypto (copy + delete): vault not overwritten", rev is None and vault.is_frozen())
ok, out = recover_ok(clean); check("crypto (copy + delete): recovered", ok, out)

# ---------------------------------------------------------------- 4 wipers
g, clean = fresh()
for p in files():
    open(p, "wb").write(b"\x00" * os.path.getsize(p))
rev, v = run(g)
check("wiper (zero-fill): named wiper", v and v["primary"] == "wiper", v and types(v))
check("wiper (zero-fill): not a crypto verdict", "crypto" not in types(v or {}))
ok, out = recover_ok(clean); check("wiper (zero-fill): recovered", ok, out)
g, clean = fresh()
for p in files():
    open(p, "wb").close()
rev, v = run(g); check("wiper (truncate to 0): named", v and v["primary"] == "wiper", v and types(v))
ok, out = recover_ok(clean); check("wiper (truncate): recovered", ok, out)
g, clean = fresh()
for p in files():
    os.remove(p)
rev, v = run(g)
check("wiper (mass delete): named + gate tripped", v and v["primary"] == "wiper" and rev is None and vault.is_frozen(), v and types(v))
ok, out = recover_ok(clean); check("wiper (mass delete): recovered", ok, out)
g, clean = fresh()
for p in files():
    open(p, "wb").write(b"\x00" * os.path.getsize(p))
note("README.txt", "Pay 2 bitcoin to the wallet to decrypt your files. private key after payment.\n")
rev, v = run(g)
wi = [t for t in v["types"] if t["type"] == "wiper"]
check("wiper posing as ransomware (note + destruction): flagged as such", wi and "posing as ransomware" in " ".join(wi[0]["why"]), v and v["types"])

# ---------------------------------------------------------------- 5 double extortion
g, clean = fresh()
src = files()[:10]                     # list BEFORE the archive exists (a zip that contains itself grows until the disk is full)
with zipfile.ZipFile("data/docs/stage_all.zip", "w") as z:
    for p in src:
        z.write(p, os.path.basename(p))
g.exfil = {"t": time.time(), "rate_mbps": 14.0, "why": "70x its recent normal"}
for p in [p for p in files() if p.endswith(".txt")]:
    b = open(p, "rb").read(); open(p, "wb").write(aes(b))
note("DECRYPT-FILES.txt", "We stole your data. Pay bitcoin or we publish and leak it. decrypt key after payment. wallet below.\n")
rev, v = run(g)
check("double extortion: named first", v and v["primary"] == "double_extortion" and "crypto" in types(v), v and types(v))
check("double extortion: says the stolen copy cannot be recalled", v and "leaked" in " ".join(v["response"]), v and v["response"])
check("double extortion: family hint Maze-like (hint only)", v and v["family_hint"] == "Maze-like", v and v["family_hint"])
check("double extortion: files still restorable", recover_ok(clean)[0])

# ---------------------------------------------------------------- 6 data theft only
g, clean = fresh()
src = files()[:10]
with zipfile.ZipFile("data/docs/everything.zip", "w") as z:
    for p in src:
        z.write(p, os.path.basename(p))
g.exfil = {"t": time.time(), "rate_mbps": 9.0, "why": "50x its recent normal"}
rev, v = run(g)
check("exfiltration only: named, no damage claimed", v and v["primary"] == "exfiltration" and "crypto" not in types(v), v and types(v))
check("exfiltration only: not a gate trip (nothing damaged)", rev is not None and not vault.is_frozen())
g2, _ = fresh(); g2.on_exfil({"t": time.time(), "rate_mbps": 9.0, "why": "test"})
check("exfiltration alarm without staged data or damage does not contain by itself", not g2.contained)
src0 = files()[0]
with zipfile.ZipFile("data/docs/x.zip", "w") as z: z.write(src0, "a")
g2.on_exfil({"t": time.time() + 1, "rate_mbps": 9.0, "why": "test"}) if not g2.exfil_recent() else None
g2.exfil = None; g2.on_exfil({"t": time.time(), "rate_mbps": 9.0, "why": "test"})
check("exfiltration with archives staged contains egress", g2.contained and os.path.exists("evidence/containment.json"))

# ---------------------------------------------------------------- 7 notes without damage
for label, text, want in (
    ("scareware", "WARNING: virus detected! Your computer is infected with a trojan. Call support now.\n", "scareware"),
    ("locker", "Your device has been locked until you pay. Unlock your device with the code you receive. bitcoin wallet.\n", "locker"),
    ("doxware", "We have your data. We will leak and publish it, sell your data and expose everything unless you pay bitcoin.\n", "doxware")):
    g, clean = fresh()
    open("data/docs/URGENT.txt", "w").write(text)
    rev, v = run(g)
    check("%s: named note_only, sub-type %s" % (label, want), v and v["primary"] == "note_only" and want in " ".join(v["types"][0]["why"]), v and v["types"])
    check("%s: nothing frozen, files untouched and committed" % label, rev is not None and not vault.is_frozen() and tree("data/docs").items() >= clean.items())

# ---------------------------------------------------------------- 8 benign must stay quiet
g, clean = fresh()
for p in files()[:5]:
    open(p, "a").write("one more line\n")
src0 = files()[0]
with zipfile.ZipFile("data/docs/report_backup.zip", "w") as z: z.write(src0, "a.txt")
open("data/docs/notes.txt", "w").write("remember to buy milk and call the plumber\n")
for p in files()[5:8]:
    if p.endswith(".txt") and "notes" not in p: os.remove(p)
rev, v = run(g)
check("benign edits, new zip, new notes, 3 deletions: no verdict", v is None, v and v["types"])
check("benign: committed, vault not frozen", rev is not None and not vault.is_frozen())
g, clean = fresh()
open("data/docs/readme.txt", "w").write("How to use this share: put your files in the folders below and ask IT for help.\n")
rev, v = run(g); check("benign readme/how-to file is not a ransom note", v is None, v and v["types"])

# ---------------------------------------------------------------- 8b live: real guard process, real wiper process
for mode in ("zero", "delete"):
    g, clean = fresh()
    cfg = dict(g.cfg, kill=True); json.dump(cfg, open("protect.json", "w"))
    log = open("guard_%s.log" % mode, "w")
    gp = subprocess.Popen([sys.executable, "-u", "guard.py", "protect.json"], stdout=log, stderr=subprocess.STDOUT)
    try:
        t0 = time.time()
        while "GUARD_ON" not in open("guard_%s.log" % mode).read() and time.time() - t0 < 15: time.sleep(0.2)
        wp = subprocess.Popen([sys.executable, "mock_wiper.py", mode, "data/docs", "--delay", "0.05"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time()
        while (("KILLED pid=" not in open("guard_%s.log" % mode).read() and "CONTAINED" not in open("guard_%s.log" % mode).read()) or "RANSOM_TYPE" not in open("guard_%s.log" % mode).read()) and time.time() - t0 < 12: time.sleep(0.2)
        L = open("guard_%s.log" % mode).read()
        if mode == "delete":     # a process that only unlinks files holds no open handle, so the kill rule cannot see who it is
            check("live delete wiper: contained (no kill: Linux does not say who deleted; needs auditd/fanotify)", "CONTAINED" in L)
        else:
            check("live %s wiper: process killed" % mode, "KILLED pid=" in L)
        check("live %s wiper: type named wiper" % mode, "RANSOM_TYPE wiper" in L, [l for l in L.splitlines() if "RANSOM_TYPE" in l][:1])
        check("live %s wiper: vault frozen" % mode, vault.is_frozen())
    finally:
        gp.terminate(); gp.wait(5)
    try: wp.wait(20)          # a wiper that could not be killed must be stopped (network cut, process found) BEFORE restoring
    except subprocess.TimeoutExpired: wp.kill()
    subprocess.run([sys.executable, "recover.py", "docs", "data/docs", "--in-place"], capture_output=True)
    check("live %s wiper: recovered bit for bit" % mode, tree("data/docs") == clean)

# ---------------------------------------------------------------- 9 outbound-transfer analyser
w = classify.ExfilWatch(min_mbps=2.0, sustain=3.0); t = 1000.0; tx = 0; fired = None
for i in range(40):
    t += 1; tx += 100_000 if i < 20 else 8_000_000
    e = w.feed(t, tx)
    fired = fired or e
check("exfil analyser: fires on a sudden sustained upload", fired and fired["rate_mbps"] >= 7, fired)
w = classify.ExfilWatch(min_mbps=2.0); t = 0; tx = 0; fired = None
for i in range(60):
    t += 1; tx += 6_000_000
    fired = fired or w.feed(t, tx)
check("exfil analyser: steady heavy upload (a normal backup) does not fire", fired is None, fired)
w = classify.ExfilWatch(min_mbps=2.0); t = 0; tx = 0; fired = None
for i in range(60):
    t += 1; tx += 100_000 if i != 30 else 9_000_000
    fired = fired or w.feed(t, tx)
check("exfil analyser: a one-second blip does not fire", fired is None, fired)

print("ALL PASS" if ok_all else "SOME FAILED"); shutil.rmtree(tmp, ignore_errors=True); sys.exit(0 if ok_all else 1)
