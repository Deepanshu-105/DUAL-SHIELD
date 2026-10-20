"""False-positive measurement on benign changes.

    python3 fp_test.py data/benign

Why not just baseline + scan? Scanning a folder against a baseline of ITSELF can
only ever report 0 flags. A false positive needs a legitimate CHANGE, so each file
gets the ordinary edits a user or program would make, and we count what the
detector (check_file: Check A + Check B) flags.

Operations (benign):
  rewrite_same   save without changes                 (every file)
  append         add a line at the end (log growth)   (text-like)
  edit_top       add a title line at the start        (text-like)
  resave_zip     re-save a zip/docx/xlsx (new times)  (zip-like)
  recompress_gz  gunzip + gzip again (new mtime)      (.gz)
"""
import collections, csv, gzip, io, math, os, shutil, sys, time, zipfile
import detect

corpus = sys.argv[1]
TEXT = {".txt",".log",".md",".csv",".html",".htm",".xml",".json",".py",".c",".h",".conf",
        ".cfg",".ini",".sh",".js",".css",".rst",".yaml",".yml",".svg"}
ZIP = {".zip", ".docx", ".xlsx", ".jar"}

def resave_zip(data):
    zin = zipfile.ZipFile(io.BytesIO(data)); out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for i in zin.infolist():
            zi = zipfile.ZipInfo(i.filename, date_time=time.localtime()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(zi, zin.read(i.filename))
    return out.getvalue()

def recompress_gz(data):
    return gzip.compress(gzip.decompress(data), mtime=int(time.time()))

OPS = [
    ("rewrite_same", lambda e: True,        lambda d: d),
    ("append",       lambda e: e in TEXT,   lambda d: d + b"\nnew log line\n"),
    ("edit_top",     lambda e: e in TEXT,   lambda d: b"# edited title\n" + d),
    ("resave_zip",   lambda e: e in ZIP,    resave_zip),
    ("recompress_gz",lambda e: e == ".gz",  recompress_gz),
]

work = corpus.rstrip("/") + "_work"
shutil.rmtree(work, ignore_errors=True); shutil.copytree(corpus, work)
base = detect.build_baseline(work)
files = sorted(base)
print("corpus: %d files" % len(files))

res = collections.defaultdict(lambda: [0, 0])      # (op, ext) -> [tested, flagged]
detail = []
for rel in files:
    p, orig = os.path.join(work, rel), os.path.join(corpus, rel)
    ext = os.path.splitext(rel)[1].lower()
    data = open(orig, "rb").read()
    for name, applies, fn in OPS:
        if not applies(ext):
            continue
        try:
            new = fn(data)
        except Exception:                           # e.g. a .zip that is not a valid zip
            continue
        open(p, "wb").write(new)
        check, why = detect.check_file(p, rel, base)
        res[(name, ext)][0] += 1
        if check:
            res[(name, ext)][1] += 1
            detail.append((name, rel, check, why))
        shutil.copyfile(orig, p)

def bound(n):                                       # rule of three: 95% upper bound for 0 events
    return 3 / n if n else float("nan")

print("\n%-14s %-8s %7s %8s" % ("operation", "type", "tested", "flagged"))
tot = collections.defaultdict(lambda: [0, 0])
for (op, ext), (n, f) in sorted(res.items()):
    print("%-14s %-8s %7d %8d" % (op, ext, n, f))
    tot[op][0] += n; tot[op][1] += f
print("\n=== False-positive rate per operation ===")
for op, (n, f) in tot.items():
    rate = "%.1f%%" % (100 * f / n) if f else "0 of %d (95%% upper bound ~%.1f%%)" % (n, 100 * bound(n))
    print("%-14s %d / %d flagged   %s" % (op, f, n, rate))
os.makedirs("evidence", exist_ok=True)
with open("evidence/fp_detail.csv", "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["operation", "file", "check", "detail"]); w.writerows(detail)
with open("evidence/fp_by_type.csv", "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["operation", "type", "tested", "flagged"])
    for (op, ext), (n, f) in sorted(res.items()): w.writerow([op, ext, n, f])
print("\nwrote evidence/fp_by_type.csv and evidence/fp_detail.csv")
