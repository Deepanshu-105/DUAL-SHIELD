"""Test tool: behaves like a wiper (destroys the files of a folder whose name ends with 'copy' or any test folder).
    python3 mock_wiper.py zero|truncate|delete <folder> [--delay 0.05]
Keeps each file open while pausing, like a real destructive process, so the kill rule can find it."""
import os, sys, time
mode, folder = sys.argv[1], sys.argv[2]
delay = float(sys.argv[sys.argv.index("--delay") + 1]) if "--delay" in sys.argv else 0.0
for root, _, names in os.walk(folder):
    for n in sorted(names):
        if n.startswith(".~ds_"):
            continue
        p = os.path.join(root, n)
        size = os.path.getsize(p)
        if mode == "delete":
            os.remove(p)
            time.sleep(delay)
            continue
        with open(p, "r+b") as f:
            if mode == "zero":
                f.write(b"\x00" * size)
            else:
                f.truncate(0)
            f.flush()
            time.sleep(delay)
print("wiped")
