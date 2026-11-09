"""One place for everything Dual-Shield does that differs between Linux and Windows. Standard library (+ psutil on Windows).

  firewall block list   Linux: ipset city_blacklist + one iptables rule     Windows: one Windows Firewall rule pair per IP (netsh)
  quarantine            Linux: iptables chain DS_QUAR                       Windows: allow-rules + default policy block in/out
  find the writer       Linux: /proc open files                             Windows: psutil open files, then biggest writers
  kill                  Linux: SIGKILL                                      Windows: TerminateProcess on the process tree (psutil)
  log folder            Linux: /var/log                                     Windows: %PROGRAMDATA%\\DualShield\\logs
  failed logons         Linux: /var/log/auth.log (ssh_parser)               Windows: Security event 4625 + OpenSSH log (detector/win_logon_watch.py)

SHIELD_OS=windows|linux forces a platform (used by the tests, which fake netsh/powershell on Linux).
Honest limits (Windows): no kernel hook, so the process that writes files is found by polling; the Windows Firewall rule per IP
is slower than an ipset (about 0.1-0.3 s per block); needs an elevated (Administrator) prompt.
"""
import ipaddress, json, os, subprocess, sys, tempfile, time

IS_WIN = (os.environ.get("SHIELD_OS") or sys.platform).lower().startswith("win")
SET = "city_blacklist"
RULE_PREFIX = "DualShield-Block-"
QUAR_PREFIX = "DualShield-Quar-Allow-"
CHAIN = "DS_QUAR"
NETSH = os.environ.get("SHIELD_NETSH", "netsh")
POWERSHELL = os.environ.get("SHIELD_POWERSHELL", "powershell")
FW_DEFAULT = os.environ.get("SHIELD_FW_DEFAULT", "blockinbound,allowoutbound")   # Windows default policy restored on release


class BlockError(Exception):
    """A firewall command failed. .stderr holds the reason."""
    def __init__(self, msg, stderr=""):
        super().__init__(msg)
        self.stderr = stderr or msg


# ------------------------------------------------------------------ files and logs
def logdir():
    d = os.environ.get("SHIELD_LOGDIR")
    if d:
        pass
    elif IS_WIN:
        d = os.path.join(os.environ.get("PROGRAMDATA", tempfile.gettempdir()), "DualShield", "logs")
    else:
        d = "/var/log"
    if IS_WIN or os.environ.get("SHIELD_LOGDIR"):
        os.makedirs(d, exist_ok=True)
    return d


def log_path(name):
    return os.path.join(logdir(), name)


def _state_path():
    return log_path("blocks.json")


def _state_load():
    try:
        with open(_state_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"blocked": [], "quarantine": False}


def _state_save(s):
    tmp = _state_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.replace(tmp, _state_path())


def _run(cmd, check=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        if check:
            raise BlockError("%s not installed" % cmd[0], "%s not installed" % cmd[0])
        return subprocess.CompletedProcess(cmd, 127, "", "%s not installed" % cmd[0])
    except subprocess.TimeoutExpired:
        if check:
            raise BlockError("%s timed out" % cmd[0])
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")
    if check and r.returncode != 0:
        raise BlockError("%s failed (rc=%d)" % (" ".join(cmd[:3]), r.returncode), (r.stderr or r.stdout).strip()[:200])
    return r


def is_admin():
    """Root on Linux, elevated Administrator on Windows."""
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return _run(["net", "session"]).returncode == 0
    return os.geteuid() == 0


# ------------------------------------------------------------------ block list (Layer 1)
def block_init():
    """Make sure the block mechanism exists. Linux: ipset + the iptables DROP rule. Windows: nothing to create (rules are per IP)."""
    if IS_WIN:
        if not is_admin() and not os.environ.get("SHIELD_OS"):
            raise BlockError("run from an elevated (Administrator) prompt")
        return
    _run(["ipset", "create", SET, "hash:ip", "-exist"], check=True)
    rule = ["INPUT", "-m", "set", "--match-set", SET, "src", "-j", "DROP"]
    if _run(["iptables", "-C", *rule]).returncode != 0:
        _run(["iptables", "-I", *rule], check=True)


def _ip(ip):
    return str(ipaddress.ip_address(ip))


def block_add(ip):
    ip = _ip(ip)
    if not IS_WIN:
        _run(["ipset", "add", SET, ip, "-exist"], check=True)
        return
    if block_test(ip):
        return
    name = RULE_PREFIX + ip
    for d in ("in", "out"):
        _run([NETSH, "advfirewall", "firewall", "add", "rule", "name=" + name, "dir=" + d, "action=block",
              "remoteip=" + ip, "enable=yes", "profile=any"], check=True)
    s = _state_load()
    if ip not in s["blocked"]:
        s["blocked"].append(ip)
        _state_save(s)


def block_del(ip):
    ip = _ip(ip)
    if not IS_WIN:
        _run(["ipset", "del", SET, ip, "-exist"], check=True)
        return
    _run([NETSH, "advfirewall", "firewall", "delete", "rule", "name=" + RULE_PREFIX + ip])   # rc 1 = already gone, fine
    s = _state_load()
    if ip in s["blocked"]:
        s["blocked"].remove(ip)
        _state_save(s)


def block_test(ip):
    ip = _ip(ip)
    if not IS_WIN:
        return _run(["ipset", "test", SET, ip]).returncode == 0
    r = _run([NETSH, "advfirewall", "firewall", "show", "rule", "name=" + RULE_PREFIX + ip])
    return r.returncode == 0 and RULE_PREFIX + ip in r.stdout


def block_list():
    if not IS_WIN:
        out = _run(["ipset", "list", SET])
        if out.returncode != 0:
            return []
        txt = out.stdout.split("Members:", 1)
        return [l.split()[0] for l in txt[1].splitlines() if l.strip()] if len(txt) == 2 else []
    return list(_state_load()["blocked"])


def block_flush():
    if not IS_WIN:
        _run(["ipset", "flush", SET])
        return
    for ip in list(_state_load()["blocked"]):
        block_del(ip)


# ------------------------------------------------------------------ quarantine (Layer 2 containment)
def quarantine_commands(allow):
    if not IS_WIN:
        c = [["iptables", "-N", CHAIN], ["iptables", "-A", CHAIN, "-i", "lo", "-j", "ACCEPT"], ["iptables", "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"]]
        for ip in allow:
            c += [["iptables", "-A", CHAIN, "-s", ip, "-j", "ACCEPT"], ["iptables", "-A", CHAIN, "-d", ip, "-j", "ACCEPT"]]
        return c + [["iptables", "-A", CHAIN, "-j", "DROP"], ["iptables", "-I", "OUTPUT", "1", "-j", CHAIN], ["iptables", "-I", "INPUT", "1", "-j", CHAIN]]
    c = []
    for ip in allow:
        for d in ("in", "out"):
            c.append([NETSH, "advfirewall", "firewall", "add", "rule", "name=" + QUAR_PREFIX + _ip(ip), "dir=" + d, "action=allow",
                      "remoteip=" + _ip(ip), "enable=yes", "profile=any"])
    c.append([NETSH, "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
    return c


def release_commands(allow=()):
    if not IS_WIN:
        return [["iptables", "-D", "OUTPUT", "-j", CHAIN], ["iptables", "-D", "INPUT", "-j", CHAIN], ["iptables", "-F", CHAIN], ["iptables", "-X", CHAIN]]
    c = [[NETSH, "advfirewall", "set", "allprofiles", "firewallpolicy", FW_DEFAULT]]
    for ip in allow:
        c.append([NETSH, "advfirewall", "firewall", "delete", "rule", "name=" + QUAR_PREFIX + _ip(ip)])
    return c


def is_quarantined():
    if not IS_WIN:
        return _run(["iptables", "-S", CHAIN]).returncode == 0
    return bool(_state_load().get("quarantine"))


def mark_quarantine(on, allow=()):
    if IS_WIN:
        s = _state_load()
        s["quarantine"] = bool(on)
        s["quarantine_allow"] = list(allow) if on else []
        _state_save(s)


def quarantine_allow_saved():
    return _state_load().get("quarantine_allow", []) if IS_WIN else []


# ------------------------------------------------------------------ processes (Layer 2 kill rule)
PROTECTED_WIN = {"system", "system idle process", "registry", "memory compression", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                 "lsass.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
                 "msmpeng.exe", "searchindexer.exe", "wudfhost.exe", "spoolsv.exe", "conhost.exe", "ctfmon.exe", "runtimebroker.exe",
                 "lsm.exe", "audiodg.exe", "dllhost.exe", "securityhealthservice.exe", "git.exe"}
PROTECTED_LINUX = {"systemd", "systemd-journal", "systemd-journald", "rsyslogd", "sshd", "dbus-daemon", "dockerd", "containerd", "agetty", "login", "init", "cron"}


def _psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def _protected_name(name):
    n = (name or "").lower()
    return n in (PROTECTED_WIN if IS_WIN else PROTECTED_LINUX)


def ancestors():
    """PIDs the kill rule must never touch: ourselves, our parent chain, init/System."""
    safe = {0, 1, 4, os.getpid()}
    ps = _psutil()
    if ps is not None:
        try:
            p = ps.Process(os.getpid())
            for a in p.parents():
                safe.add(a.pid)
        except Exception:
            pass
        return safe
    pid = os.getpid()
    while pid > 1:
        try:
            with open("/proc/%d/stat" % pid) as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
        safe.add(pid)
    return safe


def pids_with_open_file_under(folder):
    folder = os.path.normcase(os.path.realpath(folder)) + os.sep
    found = set()
    ps = _psutil()
    if IS_WIN and ps is None:
        return found
    if ps is not None and (IS_WIN or not os.path.isdir("/proc")):
        for p in ps.process_iter(["pid", "name"]):
            if _protected_name(p.info.get("name")):
                continue
            try:
                for of in p.open_files():
                    if os.path.normcase(os.path.realpath(of.path)).startswith(folder):
                        found.add(p.info["pid"])
                        break
            except Exception:       # AccessDenied, NoSuchProcess, ZombieProcess, Windows handle quirks
                continue
        return found
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % entry.name
        try:
            for fd in os.listdir(fd_dir):
                try:
                    if os.readlink(os.path.join(fd_dir, fd)).startswith(folder):
                        found.add(int(entry.name))
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return found


def pids_by_cmdline(needles):
    found = set()
    ps = _psutil()
    if ps is not None and (IS_WIN or not os.path.isdir("/proc")):
        for p in ps.process_iter(["pid", "cmdline"]):
            cmd = " ".join(p.info.get("cmdline") or [])
            if any(n in cmd for n in needles):
                found.add(p.info["pid"])
        return found
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % entry.name, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        if any(n in cmd for n in needles):
            found.add(int(entry.name))
    return found


class WriterTracker:
    """Who is writing a lot right now? Samples every process's cumulative write bytes (psutil) and reports the biggest growth since
    the previous sample. Used when no process is seen holding a file open (Windows ransomware often opens, writes, closes quickly).
    Best effort: it ranks processes, it does not prove which one wrote which file."""
    def __init__(self, keep=3):
        self.prev, self.t, self.keep = {}, 0.0, keep

    def sample(self):
        ps = _psutil()
        cur = {}
        if ps is None:
            return []
        for p in ps.process_iter(["pid", "name"]):
            if _protected_name(p.info.get("name")):
                continue
            try:
                cur[p.info["pid"]] = p.io_counters().write_bytes
            except Exception:
                continue
        now = time.time()
        fresh = self.prev and now - self.t < 10
        out = []
        if fresh:
            deltas = sorted(((cur[pid] - self.prev.get(pid, cur[pid]), pid) for pid in cur), reverse=True)
            out = [pid for d, pid in deltas if d > 0][:self.keep]
        self.prev, self.t = cur, now
        return out


def pid_alive(pid):
    ps = _psutil()
    if ps is not None:
        try:
            p = ps.Process(pid)
            return p.is_running() and p.status() != ps.STATUS_ZOMBIE
        except Exception:
            return False
    return os.path.exists("/proc/%d" % pid)


def kill_pid(pid):
    """Kill a process (and on Windows its children). Raises PermissionError / ProcessLookupError like os.kill."""
    if not IS_WIN:
        import signal
        os.kill(pid, signal.SIGKILL)
        return
    ps = _psutil()
    if ps is None:
        raise RuntimeError("psutil is needed on Windows (pip install psutil)")
    try:
        p = ps.Process(pid)
        for c in p.children(recursive=True):
            try:
                c.kill()
            except ps.Error:
                pass
        p.kill()
    except ps.NoSuchProcess:
        raise ProcessLookupError(pid)
    except ps.AccessDenied:
        raise PermissionError(pid)


def tx_bytes():
    """Bytes sent on all non-loopback interfaces, or None."""
    ps = _psutil()
    if ps is not None and (IS_WIN or not os.path.exists("/proc/net/dev")):
        try:
            return sum(c.bytes_sent for n, c in ps.net_io_counters(pernic=True).items() if not n.lower().startswith(("lo", "loopback")))
        except Exception:
            return None
    try:
        tot = 0
        for line in open("/proc/net/dev").read().splitlines()[2:]:
            name, rest = line.split(":", 1)
            if name.strip() != "lo":
                tot += int(rest.split()[8])
        return tot
    except (OSError, ValueError, IndexError):
        return None


# ------------------------------------------------------------------ Windows event log
def powershell(script, timeout=60):
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr
