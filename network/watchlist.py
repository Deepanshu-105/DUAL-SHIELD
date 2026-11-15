"""v13.7 watchlist: a threat that ONE node reported but the chain has not confirmed yet (below the quorum) is put on a short local watchlist.
A detector on any other node then reacts faster to that IP (threshold 1 instead of 3), so a second independent report can reach the quorum.
It never blocks by itself: only the detector's own sighting and the chain's consensus block.  The same file also remembers which IPs
THIS node saw itself, so the listener can log whether a consensus block has local evidence."""
import json, os, tempfile, time
TTL = float(os.environ.get("WATCH_TTL", "600"))
PATH = os.environ.get("WATCH_FILE") or os.path.join(tempfile.gettempdir(), "dualshield_watch.json")

def _load():
    try:
        with open(PATH) as f: d = json.load(f)
    except Exception: d = {}
    now = time.time()
    return {k: v for k, v in d.items() if isinstance(v, dict) and v.get("exp", 0) > now}

def _save(d):
    tmp = PATH + ".%d.tmp" % os.getpid()
    with open(tmp, "w") as f: json.dump(d, f)
    os.replace(tmp, PATH)

def watch(ip):
    d = _load(); e = d.get(ip, {}); e["exp"] = time.time() + TTL; e["watch"] = True; d[ip] = e; _save(d)

def saw(ip):
    d = _load(); e = d.get(ip, {}); e["exp"] = max(e.get("exp", 0), time.time() + TTL); e["seen"] = True; d[ip] = e; _save(d)

def is_watched(ip): return bool(_load().get(ip, {}).get("watch"))
def was_seen(ip): return bool(_load().get(ip, {}).get("seen"))
