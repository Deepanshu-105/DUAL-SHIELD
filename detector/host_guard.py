#!/usr/bin/env python3
"""Host attack guard for T/P: reverse shells, crypto miners and programs started from temp folders.
DETECT (process scan of /proc), BLOCK (kill the process, block its remote address in and out, report it to the chain), RETRIEVE (the program file
is moved to a quarantine with a record, so it can be examined or restored: --list / --restore ID).

  python3 detector/host_guard.py              # loop every HG_EVERY seconds (default 3)
  python3 detector/host_guard.py --once       # one scan, prints findings
  python3 detector/host_guard.py --list | --restore ID

HIGH (killed): reverse-shell command lines (bash -i, /dev/tcp/, nc/ncat -e, mkfifo+nc, socat exec, python/perl/ruby socket shells) and miners
(xmrig, minerd, cpuminer, stratum+tcp://, --donate-level). ALERT only (never killed, to avoid false positives): a program running from /tmp, /dev/shm,
/var/tmp or whose file was deleted (fileless). Never touched: this guard, its parents, DualShield processes, HG_ALLOW (regex on the command line).
Only program files under /tmp, /dev/shm, /var/tmp, /home, /root, /opt are quarantined; system programs (/usr, /bin ...) are never moved.
Honest limit: a renamed miner with a quiet command line and a shell that is not recognisable can pass; root can stop this guard.
"""
import json, os, re, shutil, signal, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "network")); sys.path.insert(0, os.path.join(ROOT, "multi"))
PROC = os.environ.get("HG_PROC", "/proc")
QUAR = os.environ.get("HG_QUAR", "/var/lib/dualshield/host_quarantine")
EVERY = float(os.environ.get("HG_EVERY", "3"))
ALLOW = re.compile(os.environ.get("HG_ALLOW", r"(?!x)x"))
TMP = ("/tmp/", "/dev/shm/", "/var/tmp/")
MOVABLE = ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/root/", "/opt/")
SHELL = [
 ("reverse shell (/dev/tcp)", re.compile(r"/dev/(tcp|udp)/\d|/inet/tcp/\d")),
 ("interactive shell on a network connection", re.compile(r"\b(bash|sh|zsh|dash)\s+-i\b")),      # only HIGH when the process is itself a shell AND has a remote connection
 ("reverse shell (netcat -e)", re.compile(r"(?i)\b(nc|ncat|netcat)\b.*(\s-(e|c)\b|\s--(sh-)?exec\b)|\bmkfifo\b.*\b(nc|ncat)\b")),
 ("reverse shell (zsh ztcp)", re.compile(r"\bztcp\b")),
 ("reverse shell (socat)", re.compile(r"(?i)\bsocat\b.*\b(exec|system):")),
 ("reverse shell (script socket)", re.compile(r"(?is)\b(python[0-9.]*|perl|ruby|php[0-9.]*|node|lua)\b(?=.*(socket|sockopen|net\.connect|net'\)\.connect))(?=.*(/bin/(ba)?sh|pty\.spawn|subprocess|exec|dup2|spawn|popen|system\b|os\.execute|shell_exec|proc_open|\bsystem\b))")),
 ("reverse shell (openssl / telnet pipe)", re.compile(r"(?i)openssl\s+s_client.*\|\s*(/bin/)?(ba)?sh|(/bin/)?(ba)?sh\s*\|\s*openssl|\btelnet\b.*\|\s*(/bin/)?(ba)?sh\b.*\|\s*telnet")),
]
MINER_NAME = re.compile(r"(?i)^(xmrig.*|minerd.*|cpuminer.*|ethminer|nbminer|kdevtmpfsi|kinsing|kthreaddi|xmr-stak.*|lolminer.*|t-rex.*|trex.*|phoenixminer.*|teamredminer.*|gminer.*|bzminer.*|srbminer.*|rigel.*|nanominer.*)$")        # the PROGRAM name (not any word in a command line)
MINER_ARGS = re.compile(r"(?i)(stratum\+(tcp|ssl)://|--donate-level|\b(minexmr|supportxmr|nanopool|hashvault|moneroocean|f2pool|2miners)\.|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b)")
SHELL_NAMES = ("bash", "sh", "zsh", "dash", "busybox")


def read(path, mode="r"):
    try:
        with open(path, mode + ("b" if mode == "r" else "")) as f: return f.read()
    except OSError: return None


def procs(proc=None):
    proc = proc or PROC
    try: names = [n for n in os.listdir(proc) if n.isdigit()]
    except OSError: return
    for n in names:
        d = os.path.join(proc, n); raw = read(os.path.join(d, "cmdline"))
        if raw is None: continue
        cmd = " ".join(x for x in raw.decode(errors="replace").split("\0") if x)
        try: exe = os.readlink(os.path.join(d, "exe"))
        except OSError: exe = ""
        try: ppid = int((read(os.path.join(d, "stat")) or b"").decode().rsplit(")", 1)[1].split()[1])
        except (IndexError, ValueError): ppid = 0
        yield int(n), ppid, cmd, exe, d


def remotes(d, proc=None):
    """Established remote IPv4 addresses of one process (socket inodes of its fds matched against /proc/net/tcp)."""
    proc = proc or PROC; inodes = set()
    try:
        for fd in os.listdir(os.path.join(d, "fd")):
            try: t = os.readlink(os.path.join(d, "fd", fd))
            except OSError: continue
            m = re.match(r"socket:\[(\d+)\]", t)
            if m: inodes.add(m.group(1))
    except OSError: return []
    out = []
    for ln in (read(os.path.join(proc, "net", "tcp")) or b"").decode().splitlines()[1:]:
        f = ln.split()
        if len(f) > 9 and f[3] == "01" and f[9] in inodes:
            h = f[2].split(":")[0]
            ip = ".".join(str(int(h[i:i + 2], 16)) for i in (6, 4, 2, 0))
            out.append(ip)
    return sorted(set(out))


def judge(cmd, exe):
    """-> ("HIGH", why) / ("ALERT", why) / None"""
    exe_name = os.path.basename((exe or "").replace(" (deleted)", ""))
    argv0 = os.path.basename(cmd.split(" ", 1)[0].lstrip("-")) if cmd else ""
    for why, rx in SHELL:
        if why.startswith("interactive shell") and exe_name not in SHELL_NAMES: continue      # "ssh -t host bash -i" is ssh, not a shell
        if rx.search(cmd): return "HIGH", why
    if MINER_NAME.match(exe_name) or MINER_NAME.match(argv0) or MINER_ARGS.search(cmd): return "HIGH", "crypto miner"
    if (exe or "").endswith(" (deleted)"): return "ALERT", "running from a deleted file (fileless)"
    if (exe or "").startswith(TMP): return "ALERT", "program started from %s" % os.path.dirname(exe)
    return None


class HostGuard:
    def __init__(self, kill, quarantine, block, report, never_block, proc=None, me=None, log=print):
        self.kill, self.quarantine, self.block, self.report, self.never, self.proc, self.log = kill, quarantine, block, report, never_block, proc, log
        self.me = me or os.getpid(); self.done = set()
    def protected(self, pid, ppid, cmd, tree):
        if pid == self.me or pid in tree or ALLOW.search(cmd): return True
        return bool(re.search(r"(dualshield|host_guard\.py|web_guard\.py|node_watch\.py|blockkeeper\.py|multi/agent\.py|listener\.py|peer_trust\.py)", cmd))
    def scan(self):
        found = []; rows = list(procs(self.proc)); parent = {p: pp for p, pp, *_ in rows}
        tree = set(); x = self.me
        while x and x not in tree: tree.add(x); x = parent.get(x, 0)
        for pid, ppid, cmd, exe, d in rows:
            j = judge(cmd, exe)
            if not j or self.protected(pid, ppid, cmd, tree): continue
            level, why = j; key = (pid, why)
            if why.startswith("interactive shell") and not remotes(d, self.proc): continue      # an admin's own "bash -i" is not an attack
            if key in self.done: continue
            self.done.add(key); r = {"pid": pid, "level": level, "why": why, "cmd": cmd[:160], "exe": exe, "remote": remotes(d, self.proc), "actions": []}
            if level == "HIGH":
                self.kill(pid); r["actions"].append("killed")
                if exe and exe.startswith(MOVABLE):
                    q = self.quarantine(exe, r)
                    if q: r["actions"].append("quarantined as " + q)
                for ip in r["remote"]:
                    why_not = self.never(ip)
                    if why_not: r["actions"].append("remote %s not blocked (%s)" % (ip, why_not)); continue
                    self.block(ip); self.report(ip); r["actions"].append("blocked+reported " + ip)
                self.log("HOST_ATTACK %s pid=%d %s | %s | %s" % (level, pid, why, r["cmd"], "; ".join(r["actions"]) or "no action"))
            else:
                self.log("HOST_ALERT pid=%d %s | %s" % (pid, why, r["cmd"]))
            found.append(r)
        return found


def quarantine_file(exe, rec, qdir=None):
    qdir = qdir or QUAR; path = exe.replace(" (deleted)", "")
    if not os.path.isfile(path): return None
    os.makedirs(qdir, exist_ok=True); os.chmod(qdir, 0o700)
    qid = "%d_%d" % (int(time.time()), rec["pid"]); dst = os.path.join(qdir, qid + ".bin")
    shutil.move(path, dst); os.chmod(dst, 0)
    json.dump({"id": qid, "original": path, "why": rec["why"], "cmd": rec["cmd"], "time": time.strftime("%F %T")}, open(os.path.join(qdir, qid + ".json"), "w"))
    return qid


def list_q(qdir=None):
    qdir = qdir or QUAR
    return [json.load(open(os.path.join(qdir, f))) for f in sorted(os.listdir(qdir)) if f.endswith(".json")] if os.path.isdir(qdir) else []


def restore_q(qid, qdir=None):
    qdir = qdir or QUAR; meta = json.load(open(os.path.join(qdir, qid + ".json"))); src = os.path.join(qdir, qid + ".bin")
    os.makedirs(os.path.dirname(meta["original"]), exist_ok=True); shutil.move(src, meta["original"]); os.chmod(meta["original"], 0o600)
    os.remove(os.path.join(qdir, qid + ".json")); return meta["original"]      # restored WITHOUT execute permission on purpose


def real():
    import block_policy
    infra = block_policy.local_infra()
    def kill(pid):
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass
    def block(ip):
        import shield_os; shield_os.block_init(); shield_os.block_add(ip)
        subprocess.run(["iptables", "-C", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True).returncode == 0 or subprocess.run(["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"], capture_output=True)
    def report(ip):
        subprocess.run([sys.executable, os.path.join(ROOT, "network", "chain_report.py"), ip], env=dict(os.environ, PYTHONPATH=os.path.join(ROOT, "network")), capture_output=True, timeout=60)
    def never(ip):
        try: return block_policy.never_block_reason(ip, infra)
        except ValueError: return "not an IP address"
    return HostGuard(kill, quarantine_file, block, report, never, log=lambda m: print(time.strftime("%H:%M:%S ") + m, flush=True))


if __name__ == "__main__":
    if "--list" in sys.argv:
        for m in list_q(): print("%(id)s  %(time)s  %(original)s  (%(why)s)" % m)
        sys.exit(0)
    if "--restore" in sys.argv:
        print("restored to", restore_q(sys.argv[sys.argv.index("--restore") + 1]), "(without execute permission)"); sys.exit(0)
    g = real()
    if "--once" in sys.argv:
        r = g.scan(); print("HOST_GUARD: %d finding(s)" % len(r)); sys.exit(1 if r else 0)
    print("HOST_GUARD on (every %g s)" % EVERY, flush=True)
    while True:
        try: g.scan()
        except Exception as e: print("HOST_GUARD error: %s" % e, flush=True)
        time.sleep(EVERY)
