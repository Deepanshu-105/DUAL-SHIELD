"""Kill rule: 3 distinct flagged files within 2 seconds -> os.kill(pid, 9).

Used by detect.py watch mode. One overwrite raises two modify events, so the
rule counts DISTINCT file paths, never raw events.

Finding the process that wrote the file
---------------------------------------
watchdog events carry no PID. We look for the writer in /proc:
  1. any process holding a file open under the watched folder (checked at
     every flag, so a process seen at flag 1 or 2 is still known at flag 3);
  2. LAB FALLBACK: a process whose command line contains one of
     FALLBACK_CMDLINE (the simulator). This only exists so the demo cannot
     silently fail; it is not a real attribution method.
A production tool would use fanotify, which reports the PID with each event.
"""
import collections
import os
import signal
import time

THRESHOLD = 3          # distinct flagged files ...
WINDOW_S = 2.0         # ... inside this many seconds
FALLBACK_CMDLINE = ("mock_crypto",)


def _ancestors():
    """PIDs we must never kill: init, ourselves, and our parent chain."""
    safe, pid = {0, 1, os.getpid()}, os.getpid()
    while pid > 1:
        try:
            with open("/proc/%d/stat" % pid) as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
        safe.add(pid)
    return safe


def pids_with_open_file_under(folder):
    """PIDs that currently have a file open inside `folder`."""
    folder = os.path.realpath(folder) + os.sep
    found = set()
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
        except OSError:          # process gone, or not ours
            continue
    return found


def pids_by_cmdline(needles):
    found = set()
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


class KillRule:
    def __init__(self, watch_dir, threshold=THRESHOLD, window=WINDOW_S, dry_run=False):
        self.watch_dir = watch_dir
        self.threshold, self.window, self.dry_run = threshold, window, dry_run
        self.recent = collections.OrderedDict()   # rel path -> time of latest flag
        self.suspects = set()                     # writers seen at earlier flags
        self.cooldown_until = 0.0
        self.safe = _ancestors()

    def on_flag(self, rel):
        """Call once per FLAGGED line. Returns the list of killed PIDs (usually [])."""
        now = time.monotonic()
        if now < self.cooldown_until:
            return []

        # sliding window over distinct files
        for p in [p for p, t in self.recent.items() if now - t > self.window]:
            del self.recent[p]
        self.recent.pop(rel, None)
        self.recent[rel] = now

        # remember who has the folder open right now (cheap, one /proc pass)
        self.suspects |= pids_with_open_file_under(self.watch_dir) - self.safe

        if len(self.recent) < self.threshold:
            return []

        t_trigger = time.time()
        print("%.6f KILL_TRIGGER distinct_files=%d" % (t_trigger, len(self.recent)), flush=True)
        targets, how = self.suspects & self._alive(self.suspects), "open-file"
        if not targets:
            targets, how = pids_by_cmdline(FALLBACK_CMDLINE) - self.safe, "cmdline-fallback"
        killed = []
        for pid in sorted(targets):
            if self.dry_run:
                print("%.6f DRY_RUN would kill pid=%d (%s)" % (time.time(), pid, how), flush=True)
                continue
            try:
                os.kill(pid, signal.SIGKILL)          # os.kill(pid, 9)
                killed.append(pid)
                print("%.6f KILLED pid=%d (%s)" % (time.time(), pid, how), flush=True)
            except ProcessLookupError:
                pass
            except PermissionError:
                print("%.6f KILL_DENIED pid=%d" % (time.time(), pid), flush=True)
        if not targets:
            print("%.6f KILL_NO_TARGET" % time.time(), flush=True)
        self.recent.clear()
        self.suspects.clear()
        self.cooldown_until = now + self.window       # ignore the dead process's queued events
        return killed

    @staticmethod
    def _alive(pids):
        return {p for p in pids if os.path.exists("/proc/%d" % p)}
