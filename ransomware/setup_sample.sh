#!/usr/bin/env bash
# Create the demo sample folder (10 files) and the detector baseline if they are missing.
# ransomware/data/ and baseline.json are git-ignored, so a fresh clone needs this once.
# Safe to run any time: it never overwrites an existing sample or baseline.
cd "$(dirname "$0")" || exit 1
mkdir -p evidence data
if [ "$(ls data/sample 2>/dev/null | wc -l)" -lt 10 ]; then
python3 - << 'PY'
import os, random, zipfile
random.seed(7)
os.makedirs("data/sample", exist_ok=True)
for i in range(1, 7):                         # six text logs, 12801 bytes each
    text, n = "", 0
    while len(text) < 12801:
        n += 1
        text += "2026-10-19 15:02:%02d host%d app[%d]: event %d status=ok user=u%d\n" % (n % 60, i, 1000 + i, n, random.randint(1, 99))
    open("data/sample/log%d.txt" % i, "w").write(text[:12801])
for i in range(1, 4):                         # three random binaries, 20000 bytes each
    open("data/sample/random%d.bin" % i, "wb").write(random.randbytes(20000))
with zipfile.ZipFile("data/sample/archive.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("notes.txt", "dual-shield demo archive\n" * 20)
print("sample created: 10 files in ransomware/data/sample")
PY
fi
[ -d data/sample_copy ] || cp -r data/sample data/sample_copy   # the watcher needs this folder to exist
if [ ! -f baseline.json ]; then
  python3 detect.py baseline data/sample
fi
