#!/usr/bin/env python3
"""Same as setup_sample.sh, for Windows (and anywhere): creates the 10-file demo folder, data/sample_copy and the detector baseline
if they are missing. Never overwrites an existing sample or baseline."""
import os, random, shutil, subprocess, sys, zipfile
HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
os.makedirs("evidence", exist_ok=True); os.makedirs("data", exist_ok=True)
if len(os.listdir("data/sample")) < 10 if os.path.isdir("data/sample") else True:
    random.seed(7)
    os.makedirs("data/sample", exist_ok=True)
    for i in range(1, 7):
        text, n = "", 0
        while len(text) < 12801:
            n += 1
            text += "2026-10-19 15:02:%02d host%d app[%d]: event %d status=ok user=u%d\n" % (n % 60, i, 1000 + i, n, random.randint(1, 99))
        with open("data/sample/log%d.txt" % i, "w", newline="\n") as f:
            f.write(text[:12801])
    for i in range(1, 4):
        with open("data/sample/random%d.bin" % i, "wb") as f:
            f.write(random.randbytes(20000))
    with zipfile.ZipFile("data/sample/archive.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("notes.txt", "dual-shield demo archive\n" * 20)
    print("sample created: 10 files in ransomware/data/sample")
if not os.path.isdir("data/sample_copy"):
    shutil.copytree("data/sample", "data/sample_copy")
if not os.path.exists("baseline.json"):
    subprocess.run([sys.executable, "detect.py", "baseline", "data/sample"], check=False)
