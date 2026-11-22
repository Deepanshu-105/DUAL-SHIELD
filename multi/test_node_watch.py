#!/usr/bin/env python3
import os, sys, tempfile
R = tempfile.mkdtemp(); os.environ.update(NW_ROOT=R, NW_STATE=os.path.join(R, "state.json"), NW_LOG=os.path.join(R, "nw.log"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import node_watch as nw
bad = []
def check(n, ok): print(("PASS " if ok else "FAIL ") + n); ok or bad.append(n)
def w(path, text, mode=None):
    f = os.path.join(R, path.lstrip("/")); os.makedirs(os.path.dirname(f), exist_ok=True); open(f, "w").write(text)
    if mode: os.chmod(f, mode)
w("/etc/passwd", "root:x:0:0:r:/root:/bin/bash\nvinit:x:1000:1000::/home/vinit:/bin/bash\n")
w("/proc/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 0\n   1: 0100007F:0CB0 00000000:0000 0A 0\n   2: 0100007F:9999 0100007F:0016 01 0\n")
w("/proc/modules", "ip_set 1 0 - Live 0x0\n")
w("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA admin\n"); w("/etc/crontab", "# empty\n"); w("/usr/bin/sudo", "x", 0o4755); w("/usr/bin/ls", "x", 0o755)
nw.save_base(nw.snap())
check("clean node = no findings", nw.Watch().once() == [])
check("LISTEN ports only (22 and 3248), not connected sockets", nw.snap()["listeners"] == ["tcp:22", "tcp:3248"])
x = nw.Watch()
w("/proc/net/tcp", open(os.path.join(R, "proc/net/tcp")).read() + "   3: 00000000:115C 00000000:0000 0A 0\n")
r = x.once(); check("new listening port (4444) = HIGH", any(s == "HIGH" and "tcp:4444" in m for s, m in r))
check("same finding is reported only once", x.once() == [])
w("/etc/passwd", open(os.path.join(R, "etc/passwd")).read() + "toor:x:0:0::/root:/bin/sh\n"); r = x.once(); check("new uid-0 account = CRITICAL", any(s == "CRITICAL" and "toor" in m for s, m in r))
w("/etc/ld.so.preload", "/tmp/evil.so\n"); r = x.once(); check("ld.so.preload = CRITICAL", any(s == "CRITICAL" and "preload" in m for s, m in r))
w("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA admin\nssh-rsa BBBB attacker\n"); r = x.once(); check("authorized_keys changed = HIGH", any("authorized_keys" in m for s, m in r))
w("/etc/cron.d/backdoor", "* * * * * root /tmp/x\n"); w("/etc/systemd/system/evil.service", "[Service]\n"); r = x.once(); check("new cron job and systemd unit = HIGH", any("cron" in m for s, m in r) and any("systemd" in m for s, m in r))
w("/usr/bin/bash2", "x", 0o4755); r = x.once(); check("new setuid program = HIGH", any("setuid" in m and "bash2" in m for s, m in r))
w("/proc/modules", "ip_set 1 0 - Live 0x0\nrootkit 1 0 - Live 0x1\n"); r = x.once(); check("new kernel module = MEDIUM", any(s == "MEDIUM" and "rootkit" in m for s, m in r))
nw.save_base(nw.snap()); check("--accept trusts the change", nw.Watch().once() == [])
nw.KEY = b"k" * 20; nw.save_base(nw.snap()); import json
d = json.load(open(nw.STATE)); d["snap"]["listeners"].append("tcp:1"); json.dump(d, open(nw.STATE, "w"))
y = nw.Watch(); y.once(); check("baseline edited without the key = CRITICAL alert", "NODEWATCH_ALERT CRITICAL baseline signature" in open(nw.LOG).read())
sys.exit(1 if bad else 0)
