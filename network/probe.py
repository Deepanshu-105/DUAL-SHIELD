import socket, sys, time
end = time.time() + float(sys.argv[1])
while time.time() < end:
    t = time.time()
    s = socket.socket()
    s.settimeout(0.2)
    try:
        s.connect(("172.30.0.10", 22)); ok = 1
    except Exception:
        ok = 0
    s.close()
    print("%.4f %d" % (t, ok), flush=True)
    time.sleep(0.01)
