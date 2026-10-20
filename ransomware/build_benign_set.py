"""Collect a varied benign corpus from files already on this machine.

    python3 build_benign_set.py data/benign 300 /usr/share /usr/lib /etc

Takes at most PER_EXT files of each extension so compressed formats (zip, gz,
png, jpg, pdf) are well represented, not just text. For the report, a Govdocs1
subset is the better corpus: drop its files into data/benign instead.
"""
import os, random, shutil, sys
dest, want, roots = sys.argv[1], int(sys.argv[2]), sys.argv[3:] or ["/usr/share", "/usr/lib"]
PER_EXT, MIN, MAX = 40, 1024, 5_000_000
KEEP = {".txt",".log",".md",".csv",".html",".htm",".xml",".json",".py",".c",".h",".conf",".cfg",
        ".ini",".sh",".js",".css",".rst",".yaml",".yml",".pdf",".png",".jpg",".jpeg",".gif",
        ".zip",".docx",".xlsx",".gz",".jar",".svg",".bin",".so"}
random.seed(1)
by_ext = {}
for root in roots:
    for r, _, names in os.walk(root):
        for n in names:
            p = os.path.join(r, n); e = os.path.splitext(n)[1].lower()
            try:
                if e in KEEP and not os.path.islink(p) and MIN <= os.path.getsize(p) <= MAX:
                    by_ext.setdefault(e, []).append(p)
            except OSError:
                pass
os.makedirs(dest, exist_ok=True)
picked = []
for e, ps in by_ext.items():
    random.shuffle(ps); picked += ps[:PER_EXT]
random.shuffle(picked)
for i, p in enumerate(picked[:want]):
    shutil.copyfile(p, os.path.join(dest, "%04d_%s" % (i, os.path.basename(p))))
print("copied %d files into %s; types: %s" % (min(want, len(picked)), dest,
      {e: min(PER_EXT, len(v)) for e, v in sorted(by_ext.items())}))
