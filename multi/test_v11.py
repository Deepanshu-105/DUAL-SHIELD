#!/usr/bin/env python3
"""v11 product-hardening checks that need no Fabric network (Linux, fake ipset/iptables/netsh):
IPv6 blocking, safe quarantine (allow list, env override, auto-release), Windows ARP/route parsing, IPv6 in the SSH parser.
    python3 multi/test_v11.py"""
import importlib, json, os, subprocess, sys, tempfile, textwrap, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TMP = tempfile.mkdtemp(prefix="v11_"); BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
bad = []
def check(n, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + n, "" if ok else extra)
    if not ok: bad.append(n)
def shim(name, body):
    p = os.path.join(BIN, name); open(p, "w").write("#!%s\n" % sys.executable + textwrap.dedent(body)); os.chmod(p, 0o755)
IPLOG = os.path.join(TMP, "ipset.log"); STATE = os.path.join(TMP, "nstate.json")
shim("ipset", 'import os,sys\nopen(os.environ["IPSET_LOG"],"a").write(" ".join(sys.argv[1:])+"\\n")\n')
shim("ip6tables", 'import sys\nsys.exit(1 if "-C" in sys.argv else 0)\n')
shim("iptables", 'import sys\nsys.exit(1 if "-C" in sys.argv else 0)\n')
shim("netsh", '''
    import json, os, sys
    st = os.environ["NETSH_STATE"]; a = sys.argv[1:]
    s = json.load(open(st)) if os.path.exists(st) else {"rules": [], "policy": "blockinbound,allowoutbound"}
    def kv(k):
        for x in a:
            if x.startswith(k + "="): return x.split("=", 1)[1]
    if a[:3] == ["advfirewall", "firewall", "add"]: s["rules"].append({"name": kv("name"), "action": kv("action")}); rc = 0
    elif a[:3] == ["advfirewall", "firewall", "delete"]:
        n = len(s["rules"]); s["rules"] = [r for r in s["rules"] if r["name"] != kv("name")]; rc = 0 if len(s["rules"]) < n else 1
    elif a[:2] == ["advfirewall", "set"]: s["policy"] = a[-1]; rc = 0
    else: rc = 2
    json.dump(s, open(st, "w")); sys.exit(rc)
''')
os.environ.update(PATH=BIN + os.pathsep + os.environ["PATH"], IPSET_LOG=IPLOG, NETSH_STATE=STATE, SHIELD_LOGDIR=os.path.join(TMP, "logs"))
sys.path.insert(0, os.path.join(ROOT, "multi")); sys.path.insert(0, os.path.join(ROOT, "ransomware")); sys.path.insert(0, os.path.join(ROOT, "detector"))
def load(osn):
    os.environ["SHIELD_OS"] = osn
    for m in ("shield_os", "containment"): sys.modules.pop(m, None)
    import shield_os; return shield_os

# ---- IPv6
so = load("linux")
so.block_init(); so.block_add("2001:db8::7"); so.block_add("198.51.100.4"); so.block_del("2001:db8::7")
log = open(IPLOG).read()
check("linux: IPv6 goes to its own ipset (family inet6), IPv4 to the normal one", "create city_blacklist6 hash:ip family inet6" in log and "add city_blacklist6 2001:db8::7 -exist" in log and "add city_blacklist 198.51.100.4 -exist" in log and "del city_blacklist6 2001:db8::7" in log, log)
so = load("windows"); so.block_add("2001:db8::9")
st = json.load(open(STATE))
check("windows: an IPv6 address gets the same firewall rules", any(r["name"] == "DualShield-Block-2001:db8::9" for r in st["rules"]), st)
os.environ["LOG_PATH"] = os.path.join(TMP, "a.log"); os.environ["SHIELD_OS"] = "linux"; os.environ["PARSER_LOG"] = os.path.join(TMP, "p.log"); os.environ["METRICS_LOG"] = os.path.join(TMP, "m.log")
sys.modules.pop("ssh_parser", None); import ssh_parser
m4 = ssh_parser.FAIL_PATTERN.search("sshd[1]: Failed password for root from 198.51.100.4 port 22 ssh2")
m6 = ssh_parser.FAIL_PATTERN.search("sshd[1]: Failed password for invalid user bob from 2001:db8::1234 port 22 ssh2")
mt = ssh_parser.FAIL_PATTERN.search("Nov  7 10:00:01 host sshd[1]: Failed password for root from 198.51.100.4 port 22 ssh2")
check("SSH parser reads IPv4 and IPv6 sources (and does not mistake the time stamp)", m4 and m4.group(1) == "198.51.100.4" and m6 and m6.group(1) == "2001:db8::1234" and mt.group(1) == "198.51.100.4")

# ---- containment product mode
so = load("windows")
import containment
class V:   # vault stub
    @staticmethod
    def freeze(r): pass
os.chdir(TMP)
ev = containment.contain("apply", [], "t", vault_mod=V)
check("apply with an empty allow list is refused (would lock the laptop out) and runs as dry", ev["mode"] == "dry" and not so.is_quarantined(), ev["mode"])
os.environ["CONTAIN_ALLOW"] = "10.0.0.5, 10.0.0.6"; os.environ["QUARANTINE_MAX_S"] = "1.5"
ev = containment.contain("apply", [], "t", vault_mod=V)
pol = json.load(open(STATE))["policy"]
check("CONTAIN_ALLOW fills the allow list and quarantine is applied", ev["mode"] == "apply" and ev["allow"] == ["10.0.0.5", "10.0.0.6"] and pol == "blockinbound,blockoutbound" and so.is_quarantined(), (ev["mode"], ev["allow"], pol))
time.sleep(2.5)
check("quarantine releases itself after QUARANTINE_MAX_S (a false alarm cannot lock a machine out)", json.load(open(STATE))["policy"] == "blockinbound,allowoutbound" and not so.is_quarantined())
os.environ["CONTAIN"] = "off"
ev = containment.contain("apply", ["10.0.0.5"], "t", vault_mod=V)
check("CONTAIN=off in the environment overrides the file", ev["mode"] == "off")
os.environ.pop("CONTAIN"); os.environ.pop("CONTAIN_ALLOW"); os.environ.pop("QUARANTINE_MAX_S")

# ---- Windows ARP watch parsing
import arp_watch
importlib.reload(arp_watch)
arp = textwrap.dedent("""
    Interface: 192.168.1.5 --- 0x7
      Internet Address      Physical Address      Type
      192.168.1.1           AA-BB-CC-DD-EE-FF     dynamic
      192.168.1.77          11-22-33-44-55-66     dynamic
      224.0.0.22            01-00-5e-00-00-16     static
      192.168.1.255         ff-ff-ff-ff-ff-ff     static
""")
n = arp_watch.parse_arp_a(arp)
check("windows `arp -a` parsed: dynamic entries only, MAC in colon form", n == {"192.168.1.1": ("aa:bb:cc:dd:ee:ff", "192.168.1.5"), "192.168.1.77": ("11:22:33:44:55:66", "192.168.1.5")}, n)
rt = "Active Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.254    192.168.1.5     50\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.5     25\n        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n"
check("windows `route print` default gateway (lowest metric)", arp_watch.parse_route_print(rt) == "192.168.1.1")
an = arp_watch.ArpAnalyzer({"192.168.1.1": "aa:bb:cc:dd:ee:ff"})
an.feed(time.time(), {"192.168.1.1": ("aa:bb:cc:dd:ee:ff", "x")}, "192.168.1.1")
out = an.feed(time.time(), {"192.168.1.1": ("de:ad:be:ef:00:01", "x")}, "192.168.1.1")
check("ARP analyser flags a changed gateway MAC (same logic on both systems)", any(o[0] == "gateway-mac-changed" for o in out), out)
print("\nALL PASS" if not bad else "\nFAILED: %s" % bad); sys.exit(1 if bad else 0)
