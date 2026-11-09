#!/usr/bin/env python3
"""Cross-platform layer test (v10). Runs on Linux and checks BOTH code paths:
  * Linux path: real shield_os functions against a fake `ipset` / `iptables`.
  * Windows path: SHIELD_OS=windows with a fake `netsh` and a fake `powershell` that behave like the real ones (rule store, record ids),
    plus real processes killed through the psutil route (the same code Windows uses).
This proves the logic and the command lines. It is NOT a run on real Windows: only a Windows machine proves netsh/Event Log behaviour.
    python3 multi/test_windows_mode.py"""
import json, os, subprocess, sys, tempfile, textwrap, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TMP = tempfile.mkdtemp(prefix="wintest_")
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
STATE = os.path.join(TMP, "netsh_state.json"); CALLS = os.path.join(TMP, "calls.log")
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)

def shim(name, body):
    p = os.path.join(BIN, name)
    open(p, "w").write("#!%s\n" % sys.executable + textwrap.dedent(body))
    os.chmod(p, 0o755)
    return p

shim("netsh", '''
    import json, os, sys
    st, calls = os.environ["NETSH_STATE"], os.environ["NETSH_CALLS"]
    a = sys.argv[1:]
    open(calls, "a").write(" ".join(a) + "\\n")
    s = json.load(open(st)) if os.path.exists(st) else {"rules": [], "policy": "blockinbound,allowoutbound"}
    def kv(k):
        for x in a:
            if x.startswith(k + "="): return x.split("=", 1)[1]
    if a[:3] == ["advfirewall", "firewall", "add"]:
        s["rules"].append({"name": kv("name"), "dir": kv("dir"), "action": kv("action"), "remoteip": kv("remoteip")})
        print("Ok."); rc = 0
    elif a[:3] == ["advfirewall", "firewall", "delete"]:
        n = len(s["rules"]); s["rules"] = [r for r in s["rules"] if r["name"] != kv("name")]
        rc = 0 if len(s["rules"]) < n else 1
        print("Ok." if rc == 0 else "No rules match the specified criteria.")
    elif a[:3] == ["advfirewall", "firewall", "show"]:
        m = [r for r in s["rules"] if r["name"] == kv("name")]
        if m: print("Rule Name:                            " + m[0]["name"]); rc = 0
        else: print("No rules match the specified criteria."); rc = 1
    elif a[:2] == ["advfirewall", "set"]:
        s["policy"] = a[-1]; print("Ok."); rc = 0
    else:
        rc = 2
    json.dump(s, open(st, "w")); sys.exit(rc)
''')
EVENTS = os.path.join(TMP, "events.json")
shim("powershell", '''
    import json, os, re, sys
    script = sys.argv[-1]
    last = int(re.search(r"\\$last=(\\d+)", script).group(1))
    ev = json.load(open(os.environ["PS_EVENTS"]))
    rows = [e for e in ev["ssh" if "OpenSSH" in script else "sec"] if e["rec"] > last]
    print(json.dumps(rows) if len(rows) != 1 else json.dumps(rows[0]))
''')
shim("ipset", '''
    import os, sys
    open(os.environ["IPSET_LOG"], "a").write(" ".join(sys.argv[1:]) + "\\n")
''')
shim("iptables", '''
    import sys
    sys.exit(1)
''')
json.dump({"rules": [], "policy": "blockinbound,allowoutbound"}, open(STATE, "w"))
base = dict(os.environ, PATH=BIN + os.pathsep + os.environ["PATH"], NETSH_STATE=STATE, NETSH_CALLS=CALLS, PS_EVENTS=EVENTS,
            IPSET_LOG=os.path.join(TMP, "ipset.log"), SHIELD_LOGDIR=os.path.join(TMP, "logs"))
os.environ.update(base)
sys.path.insert(0, os.path.join(ROOT, "multi"))
sys.path.insert(0, os.path.join(ROOT, "ransomware"))

def load(os_name):
    os.environ["SHIELD_OS"] = os_name
    for m in ("shield_os", "killrule", "containment"):
        sys.modules.pop(m, None)
    import shield_os
    return shield_os

def rules():
    return json.load(open(STATE))["rules"]

# ------------------------------------------------------------------ Linux path
so = load("linux")
so.block_add("198.51.100.7"); so.block_del("198.51.100.7")
log = open(os.environ["IPSET_LOG"]).read()
check("linux: block_add/del call ipset add/del -exist", "add city_blacklist 198.51.100.7 -exist" in log and "del city_blacklist 198.51.100.7 -exist" in log, log)
check("linux: logs go to SHIELD_LOGDIR when set", so.log_path("x.log").startswith(os.path.join(TMP, "logs")))
try:
    so.block_add("not-an-ip"); ok = False
except ValueError:
    ok = True
check("block refuses anything that is not an IP address", ok)

# ------------------------------------------------------------------ Windows firewall
so = load("windows")
check("windows mode selected", so.IS_WIN is True)
so.block_init()
so.block_add("198.51.100.7")
r = rules()
check("windows: block_add creates an inbound and an outbound block rule for the IP",
      sorted(x["dir"] for x in r if x["name"] == "DualShield-Block-198.51.100.7") == ["in", "out"] and all(x["action"] == "block" and x["remoteip"] == "198.51.100.7" for x in r), r)
check("windows: block_test sees it", so.block_test("198.51.100.7") and not so.block_test("198.51.100.8"))
so.block_add("198.51.100.7")
check("windows: blocking twice does not duplicate rules", len(rules()) == 2, rules())
check("windows: block_list reports it", so.block_list() == ["198.51.100.7"], so.block_list())
so.block_del("198.51.100.7")
check("windows: block_del removes both rules", rules() == [] and so.block_list() == [] and not so.block_test("198.51.100.7"))
so.block_del("198.51.100.7")
check("windows: unblocking an unknown IP is not an error", True)
so.block_add("198.51.100.20"); so.block_add("198.51.100.21"); so.block_flush()
check("windows: flush removes all Dual-Shield rules", rules() == [] and so.block_list() == [])

# ------------------------------------------------------------------ quarantine (containment)
os.chdir(TMP)   # containment writes evidence/containment.json relative to the working folder
import containment
cm = containment.contain("apply", ["10.0.0.5", "10.0.0.6"], "test", vault_mod=type("V", (), {"freeze": staticmethod(lambda r: None)}))
pol = json.load(open(STATE))["policy"]
check("windows: quarantine allows D and P, then blocks everything else", pol == "blockinbound,blockoutbound" and len([x for x in rules() if x["action"] == "allow"]) == 4, (pol, rules()))
check("windows: quarantine is remembered", so.is_quarantined())
containment.release(True)
check("windows: release restores the normal policy and removes the allow rules", json.load(open(STATE))["policy"] == "blockinbound,allowoutbound" and rules() == [] and not so.is_quarantined(), json.load(open(STATE)))

# ------------------------------------------------------------------ kill rule via psutil (the Windows route)
import killrule
check("system processes are protected from the kill rule (Windows)", all(so._protected_name(n) for n in ("svchost.exe", "LSASS.EXE", "explorer.exe", "System")) and not so._protected_name("mock_crypto.exe"))
work = os.path.join(TMP, "protected"); os.makedirs(work)
for i in range(5): open(os.path.join(work, "f%d.txt" % i), "w").write("x" * 100)
holder = subprocess.Popen([sys.executable, "-c", "import time,sys; f=open(sys.argv[1]+'/f0.txt','r+b'); time.sleep(60)", work])
time.sleep(1)
kr = killrule.KillRule(work)
killed = []
for i in range(3):
    killed += kr.on_flag("f%d.txt" % i)
time.sleep(0.5)
check("kill rule finds the process holding a protected file (psutil) and kills it", holder.pid in killed and holder.poll() is not None, killed)

other = os.path.join(TMP, "elsewhere"); os.makedirs(other)
writer = subprocess.Popen([sys.executable, "-c", "import os,sys,time\nb=os.urandom(1<<20)\nwhile True:\n  open(sys.argv[1]+'/blob','wb').write(b*4)\n  time.sleep(0.01)", other])
time.sleep(1)
kr = killrule.KillRule(work)
killed = []
for i in range(4):
    killed += kr.on_flag("f%d.txt" % i)
    time.sleep(0.3)
time.sleep(0.5)
check("kill rule falls back to the biggest writer when no open file is seen (open/write/close style)", writer.pid in killed and writer.poll() is not None, (killed, writer.pid))
for p in (holder, writer):
    if p.poll() is None: p.kill()

# ------------------------------------------------------------------ Windows logon events -> auth.log lines -> ssh_parser
json.dump({"sec": [{"id": 4625, "rec": 10, "user": "admin", "ip": "198.51.100.9", "lt": "3"}],
           "ssh": [{"rec": 5, "msg": "sshd: Failed password for root from 198.51.100.10 port 5 ssh2"}]}, open(EVENTS, "w"))
import importlib
sys.path.insert(0, os.path.join(ROOT, "detector"))
os.environ["LOG_PATH"] = os.path.join(TMP, "logs", "auth.log")
import win_logon_watch
importlib.reload(win_logon_watch)
w = win_logon_watch.Watcher(os.environ["LOG_PATH"])
os.makedirs(os.path.dirname(os.environ["LOG_PATH"]), exist_ok=True)
check("first poll only remembers the log position (old events are never replayed)", w.poll() == 0 and not os.path.exists(os.environ["LOG_PATH"]))
ev = json.load(open(EVENTS))
ev["sec"] += [{"id": 4625, "rec": 11, "user": "admin", "ip": "198.51.100.9", "lt": "3"},
              {"id": 4625, "rec": 12, "user": "bad user", "ip": "198.51.100.9", "lt": "10"},
              {"id": 4625, "rec": 13, "user": "x", "ip": "-", "lt": "2"},
              {"id": 4625, "rec": 14, "user": "x", "ip": "::1", "lt": "3"},
              {"id": 4625, "rec": 15, "user": "x", "ip": "127.0.0.1", "lt": "3"},
              {"id": 4624, "rec": 16, "user": "alice", "ip": "198.51.100.30", "lt": "10"},
              {"id": 4624, "rec": 17, "user": "alice", "ip": "198.51.100.31", "lt": "2"}]
ev["ssh"] += [{"rec": 6, "msg": "sshd: Failed password for invalid user bob from 198.51.100.10 port 22 ssh2"}]
json.dump(ev, open(EVENTS, "w"))
n = w.poll()
txt = open(os.environ["LOG_PATH"]).read()
check("new failed logons become 'Failed password for USER from IP' lines (users with spaces fixed)", txt.count("Failed password for admin from 198.51.100.9") == 1 and "Failed password for bad_user from 198.51.100.9" in txt, txt)
check("OpenSSH log lines are passed through", "Failed password for invalid user bob from 198.51.100.10" in txt, txt)
check("remote successful logon (type 10) is written, interactive (type 2) is not", "Accepted password for alice from 198.51.100.30" in txt and "198.51.100.31" not in txt)
check("empty, IPv6 and loopback addresses are ignored", "::1" not in txt and "127.0.0.1" not in txt and " - " not in txt)
before = len(txt)
w.poll()
check("a poll with no new events writes nothing", len(open(os.environ["LOG_PATH"]).read()) == before)

# the real parser on the Windows path: three failures -> Windows Firewall rule
open(CALLS, "w").write("")
log = os.path.join(TMP, "logs", "ssh_test_auth.log"); open(log, "w").close()
env = dict(os.environ, SHIELD_OS="windows", LOG_PATH=log, PARSER_LOG=os.path.join(TMP, "logs", "parser_block.log"), METRICS_LOG=os.path.join(TMP, "logs", "metrics.log"),
           PYTHONPATH=os.path.join(ROOT, "network"), TOR_LIST=os.path.join(TMP, "none"), TOR_LIST_EXTRA=os.path.join(TMP, "none"), WHITELIST_EXTRA="198.51.100.200")
json.dump({"rules": [], "policy": "blockinbound,allowoutbound"}, open(STATE, "w"))
p = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "detector", "ssh_parser.py")], env=env, stdout=open(os.path.join(TMP, "sp.out"), "w"), stderr=subprocess.STDOUT)
time.sleep(3)
with open(log, "a") as f:
    for i in range(3): f.write("Nov  7 10:00:0%d host sshd[1]: Failed password for root from 198.51.100.50 port 22 ssh2\n" % i)
    for i in range(5): f.write("Nov  7 10:00:1%d host sshd[1]: Failed password for root from 198.51.100.200 port 22 ssh2\n" % i)
for _ in range(30):
    time.sleep(0.5)
    if rules(): break
p.kill()
names = sorted({r["name"] for r in rules()})
check("ssh_parser on the Windows path blocks the attacker with a Windows Firewall rule", names == ["DualShield-Block-198.51.100.50"], (names, open(os.path.join(TMP, "sp.out")).read()[-400:]))
check("a whitelisted address is not blocked", "198.51.100.200" not in " ".join(names))
check("the block is logged for the peers and the expiry job", "PARSER_BLOCK ip=198.51.100.50" in open(os.path.join(TMP, "logs", "parser_block.log")).read())

# block expiry on Windows
import expire_blocks
importlib.reload(expire_blocks)
so = load("windows"); importlib.reload(expire_blocks)
open(os.path.join(TMP, "logs", "parser_block.log"), "w").write("PARSER_BLOCK ip=198.51.100.50 ts=%.3f\n" % (time.time() - 7200))
gone = expire_blocks.sweep(3600, [os.path.join(TMP, "logs", "parser_block.log")])
check("block expiry removes the Windows Firewall rule", gone == ["198.51.100.50"] and rules() == [], (gone, rules()))

print("\nALL PASS" if not bad else "\nFAILED: %s" % bad)
sys.exit(1 if bad else 0)
