"""Windows, Administrator PowerShell, in the repo:   pip install pywintrace   then   python multi\\win_etw_probe.py
Starts the kernel file listener, lets a child process write 40 files in a temp folder and prints how fast its pid is known."""
import os, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import win_etw
d = tempfile.mkdtemp(prefix="etwprobe_")
print("listener:", win_etw.start([d]), win_etw.STATE)
if not win_etw.STATE["running"]: sys.exit("ETW not running: " + str(win_etw.STATE["error"]))
time.sleep(2)
code = "import os,time;d=%r\nfor i in range(40):\n open(os.path.join(d,'f%%d.txt'%%i),'w').write('x'*100);time.sleep(0.02)" % d
t0 = time.time(); ch = subprocess.Popen([sys.executable, "-c", code]); found = None
while time.time() - t0 < 10:
    w = win_etw.writers_under(d)
    if ch.pid in w: found = time.time() - t0; break
    time.sleep(0.02)
ch.wait(); print("events seen:", win_etw.STATE["events"])
print("PROBE_OK writer pid %d known after %.2f s" % (ch.pid, found) if found is not None else "PROBE_FAIL writer not identified (send me this output)")
win_etw.stop()
