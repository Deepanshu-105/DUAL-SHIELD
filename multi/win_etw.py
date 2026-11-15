"""v13.10 Windows: which process is writing to the protected folder, in milliseconds, from the Windows KERNEL.
The kernel itself emits an event for every file create / write / rename / delete (ETW provider Microsoft-Windows-Kernel-File) with the process id.
We listen to it (no driver of our own, no reboot) and keep the last few seconds per process, so when the guard's gate trips the writers are
known at once and no 3-4 s scan of every open handle is needed.  Needs Administrator and:  pip install pywintrace
If ETW is not available the guard silently keeps using the scan (the old path).  Never kills anything itself: it only answers writers_under().
Event ids of the provider: 12 create (has FileName), 14 set-info, 15 read, 16 write, 19 rename, 26 delete-path, 27 rename-path."""
import collections, os, threading, time
GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
KEYWORDS = 0x80 | 0x200 | 0x400 | 0x800 | 0x1000      # create, write, delete-path, rename-path, new file (NOT filename/fileio/op-end: they flood the listener, which then lags behind)
EVENT_IDS = [12, 14, 16, 19, 26, 27]
WINDOW = float(os.environ.get("ETW_WINDOW", "5"))
MIN_OPS = int(os.environ.get("ETW_MIN_OPS", "3"))
_lock = threading.Lock()
_roots = []                              # normalised folders (with trailing separator)
_ops = collections.defaultdict(collections.deque)      # pid -> deque of timestamps of writes under a root
_objs = {}                               # FileObject -> (path, pid)
_job = None
_started = False
STATE = {"running": False, "error": None, "events": 0}

def _norm(p): return os.path.normcase(os.path.realpath(p)) + os.sep
def _under(path):
    path = os.path.normcase(path or "")
    # ETW file names are NT paths (\Device\HarddiskVolume3\Users\...): match on the part after the drive, case-insensitive
    for r in _roots:
        tail = r[2:] if len(r) > 2 and r[1] == ":" else r
        if tail and tail.lower() in path.lower(): return True
    return False

def feed(event_id, pid, name=None, fobj=None, now=None):
    """one kernel event -> bookkeeping (also the entry point of the unit test)"""
    now = time.time() if now is None else now
    STATE["events"] += 1
    with _lock:
        if event_id in (12, 14, 19, 26, 27) and name and _under(name):
            if fobj is not None: _objs[fobj] = (name, pid)
            if event_id in (19, 26, 27): _ops[pid].append(now)           # rename / delete inside the folder counts as a write
            elif event_id == 12: _ops[pid].append(now)                   # create (ransomware creates its encrypted copies)
        elif event_id == 16 and fobj in _objs:
            _ops[pid].append(now)
        if len(_objs) > 50000: _objs.clear()
        dq = _ops[pid]
        while dq and now - dq[0] > WINDOW: dq.popleft()

def writers_under(folder=None, min_ops=None, now=None):
    """pids that changed files under the protected folders in the last WINDOW seconds (at least min_ops operations)"""
    now = time.time() if now is None else now
    n = MIN_OPS if min_ops is None else min_ops
    out = set()
    with _lock:
        for pid, dq in list(_ops.items()):
            while dq and now - dq[0] > WINDOW: dq.popleft()
            if not dq: _ops.pop(pid, None); continue
            if len(dq) >= n: out.add(pid)
    out.discard(os.getpid())
    return out

def _callback(ev):
    try:
        eid, d = (ev[0], ev[1]) if isinstance(ev, tuple) else (None, ev)
        d = d if isinstance(d, dict) else {}
        h = d.get("EventHeader", {}) if isinstance(d.get("EventHeader"), dict) else {}
        eid = eid if eid is not None else h.get("EventDescriptor", {}).get("Id")
        pid = h.get("ProcessId") or d.get("ProcessId")
        name = d.get("FileName") or d.get("OpenPath")
        fobj = d.get("FileObject") or d.get("FileKey")
        if eid is not None and pid: feed(int(eid), int(pid), name, fobj)
    except Exception:
        pass

def start(roots):
    """returns True when the kernel listener runs"""
    global _job, _started
    if os.name != "nt": return False
    _roots[:] = [_norm(r) for r in roots]
    if _started: return STATE["running"]
    _started = True
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin(): raise PermissionError("Administrator needed for ETW")
        from etw import ETW, ProviderInfo
        from etw.GUID import GUID as G
        prov = ProviderInfo("Microsoft-Windows-Kernel-File", G(GUID), any_keywords=KEYWORDS)
        try:
            _job = ETW(providers=[prov], event_callback=_callback, event_id_filters=EVENT_IDS)     # filtered inside the library: much less work per second
        except TypeError:
            _job = ETW(providers=[prov], event_callback=_callback)
        _job.start(); STATE["running"] = True
        print("ETW_ON kernel file events, writers known within milliseconds", flush=True)
    except Exception as e:
        STATE["error"] = str(e); STATE["running"] = False
        print("ETW_OFF (%s): the scan is used instead (slower)" % e, flush=True)
    return STATE["running"]

def stop():
    global _job
    try:
        if _job: _job.stop()
    except Exception: pass
    _job = None; STATE["running"] = False
