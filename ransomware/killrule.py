"""Kill rule: 3 distinct flagged files within 2 seconds -> os.kill(pid, 9).

Used by detect.py watch mode. One overwrite raises two modify events, so the
rule counts DISTINCT file paths, never raw events.

Finding the process that wrote the file
---------------------------------------
watchdog events carry no PID. We look for the writer in /proc:
  1. any process holding a file open under the watched folder (checked at
     every flag, so a process seen at flag 1 or 2 is still known at flag 3);
  2. (v10) the processes whose write volume grew most since the previous flag (psutil; this is what Windows relies on, because
     ransomware there often opens, writes and closes files too fast to be seen holding one);
  3. LAB FALLBACK: a process whose command line contains one of
     FALLBACK_CMDLINE (the simulator). This only exists so the demo cannot
     silently fail; it is not a real attribution method.
A production tool would use fanotify, which reports the PID with each event.
"""
import collections
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os            # Linux (/proc, SIGKILL) and Windows (psutil, TerminateProcess)

THRESHOLD = 3          # distinct flagged files ...
WINDOW_S = 2.0         # ... inside this many seconds
FALLBACK_CMDLINE = ("mock_crypto",)

_ancestors = shield_os.ancestors
pids_with_open_file_under = shield_os.pids_with_open_file_under
pids_by_cmdline = shield_os.pids_by_cmdline


class KillRule:
    def __init__(self, watch_dir, threshold=THRESHOLD, window=WINDOW_S, dry_run=False):
        self.watch_dir = watch_dir
        self.threshold, self.window, self.dry_run = threshold, window, dry_run
        self.recent = collections.OrderedDict()   # rel path -> time of latest flag
        self.suspects = set()                     # writers seen at earlier flags
        self.cooldown_until = 0.0
        self.safe = _ancestors()
        self.kernel = shield_os.KernelWriters(watch_dir) if os.environ.get("KERNEL_HOOK", "1") == "1" else None   # fanotify: kernel-reported writer pids (Linux, root)
        self.writers = shield_os.WriterTracker()   # who writes most right now (used when no open file is seen)
        self.heavy = []

    def on_flag(self, rel, force=False):
        """Call once per FLAGGED line. Returns the list of killed PIDs (usually []).
        force=True skips the 3-file threshold (used when a canary/decoy file is touched)."""
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
        self.heavy = [p for p in dict.fromkeys(self.heavy + self.writers.sample()) if p not in self.safe][-6:]

        if len(self.recent) < self.threshold and not force:   # force: a decoy file was touched
            return []

        t_trigger = time.time()
        print("%.6f KILL_TRIGGER distinct_files=%d" % (t_trigger, len(self.recent)), flush=True)
        kw = {p for p in (self.kernel.writers() if self.kernel and self.kernel.ok else []) if p not in self.safe and self._alive([p])}
        targets, how = (kw, "kernel-fanotify") if kw else (self.suspects & self._alive(self.suspects), "open-file")
        if not targets:
            targets, how = {p for p in self.heavy if self._alive([p])}, "top-writer"
        if not targets:
            targets, how = pids_by_cmdline(FALLBACK_CMDLINE) - self.safe, "cmdline-fallback"
        killed = []
        for pid in sorted(targets):
            if self.dry_run:
                print("%.6f DRY_RUN would kill pid=%d (%s)" % (time.time(), pid, how), flush=True)
                continue
            try:
                shield_os.kill_pid(pid)               # Linux SIGKILL / Windows TerminateProcess of the tree
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
        self.heavy = []
        self.cooldown_until = now + self.window       # ignore the dead process's queued events
        return killed

    @staticmethod
    def _alive(pids):
        return {p for p in pids if shield_os.pid_alive(p)}
