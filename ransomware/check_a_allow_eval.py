#!/usr/bin/env python3
"""Measures the check-A allow-list (DS_CHECK_A_ALLOW) in BOTH directions, on the same corpus, OFF and ON.
    python3 check_a_allow_eval.py data/benign          (run from ransomware/; make the corpus with build_benign_set.py)
Benign side: the three operations of fp_test.py that rewrite the file start (edit_top, resave_zip, recompress_gz): how many are flagged.
Attack side (mock, on COPIES, random bytes as 'ciphertext'; no real ransomware): per attack style, how many files check A or check B still flag:
  overwrite_all      every byte replaced (the usual crypto-ransomware)
  keep_16            first 16 bytes kept, the rest replaced (header-kept, evasive)
  keep_magic         only the 3-4 byte magic number kept, the rest replaced (an attacker who knows about this allow-list)
  base64_armour      ciphertext written as base64 text (printable: the text rule cannot tell it from text)
Writes evidence/check_a_allow.csv and prints the table. One file flagged is not a kill: the kill rule needs 3 distinct files in 2 s."""
import base64, collections, csv, gzip, io, os, shutil, subprocess, sys, tempfile, time, zipfile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
corpus = sys.argv[1]
def resave_zip(d):
    zin = zipfile.ZipFile(io.BytesIO(d)); out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for i in zin.infolist():
            zi = zipfile.ZipInfo(i.filename, date_time=time.localtime()[:6]); zi.compress_type = zipfile.ZIP_DEFLATED; z.writestr(zi, zin.read(i.filename))
    return out.getvalue()
def magic_len(rel, d):
    return 4 if d[:2] == b"PK" else 3 if d[:2] == b"\x1f\x8b" else 0
def rnd(n): return os.urandom(n)
OPS = {"BENIGN edit_top (text)": (lambda e: e in {".txt",".log",".md",".csv",".html",".xml",".json",".py",".c",".h",".conf",".cfg",".ini",".sh",".js",".css",".rst",".yml",".svg"}, lambda d: b"# edited title\n" + d),
       "BENIGN resave zip/jar": (lambda e: e in {".zip", ".docx", ".xlsx", ".jar"}, resave_zip),
       "BENIGN recompress gz": (lambda e: e == ".gz", lambda d: gzip.compress(gzip.decompress(d), mtime=int(time.time()))),
       "ATTACK overwrite_all": (lambda e: True, lambda d: rnd(len(d))),
       "ATTACK keep_16": (lambda e: True, lambda d: d[:16] + rnd(max(0, len(d) - 16))),
       "ATTACK keep_magic": (lambda e: True, lambda d: d[:magic_len("", d)] + rnd(max(0, len(d) - magic_len("", d)))),
       "ATTACK base64_armour": (lambda e: True, lambda d: base64.b64encode(rnd(len(d)))[:len(d)])}
CODE = r'''
import sys, os, json, shutil, collections
sys.path.insert(0, %r); import detect
corpus, ops = sys.argv[1], json.loads(sys.argv[2])
work = corpus.rstrip("/") + "_work_allow"; shutil.rmtree(work, ignore_errors=True); shutil.copytree(corpus, work)
base = detect.build_baseline(work); res = collections.defaultdict(lambda: [0, 0, 0])
import importlib; m = importlib.import_module("check_a_allow_ops")
for rel in sorted(base):
    p, orig = os.path.join(work, rel), os.path.join(corpus, rel); ext = os.path.splitext(rel)[1].lower(); data = open(orig, "rb").read()
    for name in ops:
        applies, fn = m.OPS[name]
        if not applies(ext) or len(data) < 64: continue
        try: new = fn(data)
        except Exception: continue
        open(p, "wb").write(new); chk, _ = detect.check_file(p, rel, base)
        res[name][0] += 1; res[name][1] += 1 if chk else 0; res[name][2] += 1 if chk == "A" else 0
        shutil.copyfile(orig, p)
print(json.dumps(res))
''' % HERE
# the ops live in an importable module so the child process can use them
src = open(__file__).read(); a = src.index("def resave_zip"); b = src.index("CODE = r")
open(os.path.join(HERE, "check_a_allow_ops.py"), "w").write("import base64, gzip, io, os, time, zipfile\n" + src[a:b])
res = {}
for mode in ("0", "1"):
    env = dict(os.environ, DS_CHECK_A_ALLOW=mode)
    r = subprocess.run([sys.executable, "-c", CODE, corpus, __import__("json").dumps(list(OPS))], capture_output=True, text=True, env=env, cwd=HERE)
    if r.returncode: sys.exit(r.stderr)
    res[mode] = __import__("json").loads(r.stdout)
os.makedirs(os.path.join(HERE, "evidence"), exist_ok=True)
rows = []; print("%-26s %6s | %-22s | %-22s" % ("operation", "files", "flagged, allow-list OFF", "flagged, allow-list ON"))
for name in OPS:
    off, on = res["0"].get(name, [0, 0, 0]), res["1"].get(name, [0, 0, 0])
    if not off[0]: continue
    print("%-26s %6d | %4d (%3d%%)             | %4d (%3d%%)" % (name, off[0], off[1], 100 * off[1] // off[0], on[1], 100 * on[1] // on[0]))
    rows.append([name, off[0], off[1], on[1]])
with open(os.path.join(HERE, "evidence", "check_a_allow.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["operation", "files", "flagged_off", "flagged_on"]); w.writerows(rows)
os.remove(os.path.join(HERE, "check_a_allow_ops.py")); print("wrote evidence/check_a_allow.csv")
