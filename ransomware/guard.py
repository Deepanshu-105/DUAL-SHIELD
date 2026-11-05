"""Continuous protection service (steps 5, 6, 7).

    python3 guard.py protect.json            # run until Ctrl+C
    python3 guard.py protect.json --once     # one gated commit, then exit

Step 5  smaller loss window: every change to a protected folder schedules a vault
        commit after `debounce_s` seconds of quiet (or `max_wait_s` at most). The
        loss window is therefore ~debounce_s, not "since the last manual snapshot".
        CLEAN GATE: before each commit the live files are checked (check A header,
        check B chi-square) against the LAST COMMITTED state. Flagged files are held
        back (old vault copy kept); >= gate_threshold flagged files freezes the vault.
Step 6  contain: when the kill rule fires or the gate trips -> containment.contain().
Step 7  wider coverage: any number of roots, with exclude patterns and a size cap.
"""
import json, os, sys, threading, time

import detect, vault, containment

DEFAULTS = {"debounce_s": 2.0, "max_wait_s": 30.0, "gate_threshold": 3,
            "release_after_s": 60.0, "kill": True, "contain": "dry", "allow": [],
            "remote": "",
            "canary": False,        # decoy files in every root: touching one = instant kill (catches slow ransomware)
            "burst_files": 0,       # 0 = off. N = freeze+contain if N distinct files change within burst_window_s
            "burst_window_s": 5.0}      # remote: a git URL or path; every commit is pushed there (off-machine copy)


def load_config(path):
    cfg = dict(DEFAULTS)
    cfg.update(json.load(open(path)))
    for r in cfg["roots"]:
        r.setdefault("exclude", [])
        r.setdefault("max_mb", 0)
    return cfg


class Guard:
    def __init__(self, cfg):
        self.cfg = cfg
        self.roots = {r["name"]: r for r in cfg["roots"]}
        self.base = {}                 # name -> detector baseline of last COMMITTED state
        self.dirty_since = None        # first event of the current batch
        self.last_event = 0.0
        self.held_since = {}           # (name, rel) -> time first held
        self.lock = threading.Lock()
        self.rules = {}
        self.contained = False
        self.held = 0
        self.started = time.time()
        self.canaries = {}             # abs path -> (root name, rel)
        self.burst = []                # (ts, path) of recent modifications

    CANARY_FILES = {".~ds_canary_a.docx": "Quarterly budget draft. Do not delete.\n" * 40,
                    ".~ds_canary_b.xlsx": "id,amount,note\n" + "".join("%d,%d,reserved\n" % (i, i * 37) for i in range(80))}

    def make_canaries(self):
        """Decoy files nobody legitimate touches. Ransomware that walks the folder hits one sooner or later,
        even when it encrypts slowly or keeps file headers, which the 3-files rule and the header check miss."""
        for name, r in self.roots.items():
            if not os.path.isdir(r["path"]):
                continue
            dirs = [r["path"]] + sorted(os.path.join(r["path"], d) for d in os.listdir(r["path"])
                                         if os.path.isdir(os.path.join(r["path"], d)))[:4]
            for d in dirs:
                for fn, body in self.CANARY_FILES.items():
                    p = os.path.join(d, fn)
                    if not os.path.exists(p):
                        with open(p, "w") as f:
                            f.write(body)
                    self.canaries[os.path.abspath(p)] = (name, os.path.relpath(p, r["path"]))

    def on_canary(self, path, how):
        name, rel = self.canaries[os.path.abspath(path)]
        print("%.3f CANARY_TOUCHED %s/%s (%s)" % (time.time(), name, rel, how), flush=True)
        self.on_flag(name, rel, "C", "decoy file %s" % how, force=True)
        if not self.contained:
            self._contain("canary file %s: %s/%s" % (how, name, rel), [rel])     # no kill target found: still freeze

    def note_burst(self, path):
        n, w = self.cfg["burst_files"], self.cfg["burst_window_s"]
        if not n:
            return
        now = time.time()
        self.burst = [(t, p) for t, p in self.burst if now - t <= w] + [(now, path)]
        if len({p for _, p in self.burst}) >= n and not self.contained:
            print("%.3f BURST %d distinct files changed within %.0fs" % (now, n, w), flush=True)
            self._contain("burst: %d files changed within %.0fs" % (n, w), [os.path.basename(p) for _, p in self.burst][:20])

    def heartbeat(self):
        """evidence/guard.json: proves the guard is alive; the dashboard reads it."""
        try:
            with open("evidence/guard.json.tmp", "w") as f:
                json.dump({"t": time.time(), "started": self.started, "roots": list(self.roots),
                           "debounce_s": self.cfg["debounce_s"], "kill": self.cfg["kill"],
                           "contain": self.cfg["contain"], "held": self.held,
                           "contained": self.contained, "remote": bool(self.cfg.get("remote"))}, f)
            os.replace("evidence/guard.json.tmp", "evidence/guard.json")
        except OSError:
            pass

    # ---- baseline / commit -------------------------------------------------
    def _rebuild_baselines(self):
        for name in self.roots:
            d = os.path.join(vault.VAULT, "files", name)
            self.base[name] = detect.build_baseline(d) if os.path.isdir(d) else {}

    def start(self):
        os.makedirs("evidence", exist_ok=True)
        if not os.path.isdir(os.path.join(vault.VAULT, ".git")):
            vault.init(self.cfg["roots"][0]["path"])
        if self.cfg.get("remote"):
            vault.init(self.cfg["roots"][0]["path"], self.cfg["remote"])
        if vault.is_frozen():
            print("GUARD_FROZEN vault is frozen; restore then run: python3 vault.py unfreeze")
            return False
        if self.cfg.get("canary"):
            self.make_canaries()
        if not vault.sh("git", "log", "--oneline", "-1", check=False).stdout.strip():
            vault.commit_roots(self.cfg["roots"], "initial")   # first snapshot assumed clean
        if any(not os.path.isdir(os.path.join(vault.VAULT, "files", n)) for n in self.roots):
            vault.commit_roots(self.cfg["roots"], "layout-migrate")   # old single-folder vault
        self._rebuild_baselines()
        return True

    def scan(self):
        """name -> {rel: check letter} for live files that differ suspiciously."""
        out = {}
        for name, r in self.roots.items():
            if not os.path.isdir(r["path"]):
                continue
            for p, rel in detect.all_files(r["path"]):
                chk, _ = detect.check_file(p, rel, self.base.get(name, {}))
                if chk:
                    out.setdefault(name, {})[rel] = chk
        return out

    def gated_commit(self, label="auto"):
        with self.lock:
            if vault.is_frozen():
                return None
            flagged = self.scan()
            now = time.time()
            n = sum(len(v) for v in flagged.values())
            if n >= self.cfg["gate_threshold"]:
                names = ["%s/%s" % (k, rel) for k, v in flagged.items() for rel in v]
                print("GATE_TRIPPED %d suspicious files, commit skipped" % n, flush=True)
                self._contain("gate: %d files flagged" % n, names)
                return None
            hold = {}
            for name, files in flagged.items():
                for rel, chk in files.items():
                    first = self.held_since.setdefault((name, rel), now)
                    # an isolated header-only change (check A) is probably a real edit:
                    # accept it after release_after_s. Check B (looks encrypted) never is.
                    if chk == "A" and now - first >= self.cfg["release_after_s"]:
                        print("GATE_RELEASED %s/%s (isolated header change)" % (name, rel))
                        continue
                    hold.setdefault(name, set()).add(rel)
                    print("GATE_HELD [check %s] %s/%s" % (chk, name, rel), flush=True)
            for k in [k for k in self.held_since if k[1] not in flagged.get(k[0], {})]:
                del self.held_since[k]
            rev = vault.commit_roots(self.cfg["roots"], label, hold)
            self._rebuild_baselines()
            self.held = sum(len(v) for v in hold.values())
            if rev and self.cfg.get("remote"):
                threading.Thread(target=vault.push, daemon=True).start()
            return rev

    # ---- containment -------------------------------------------------------
    def _contain(self, reason, files):
        if self.contained:
            return
        self.contained = True
        containment.contain(self.cfg["contain"], self.cfg["allow"], reason, files)

    # ---- events ------------------------------------------------------------
    def mark_dirty(self):
        now = time.time()
        with self.lock:
            if self.dirty_since is None:
                self.dirty_since = now
            self.last_event = now

    def on_flag(self, name, rel, chk, detail, force=False):
        print("%.3f FLAGGED [check %s] %s/%s  %s" % (time.time(), chk, name, rel, detail), flush=True)
        rule = self.rules.get(name)
        if rule:
            before = rule.cooldown_until
            rule.on_flag(rel, force=force)
            if rule.cooldown_until != before:          # kill rule fired
                self._contain("kill rule fired on %s" % name, [rel])

    def run(self):
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        g = self
        if self.cfg["kill"]:
            from killrule import KillRule
            for name, r in self.roots.items():
                self.rules[name] = KillRule(r["path"])

        def handler(name, root):
            class H(FileSystemEventHandler):
                def on_any_event(self, ev):
                    if ev.is_directory or ev.event_type == "opened" or ev.event_type == "closed_no_write":
                        return
                    g.mark_dirty()
                    for p in (ev.src_path, getattr(ev, "dest_path", "")):
                        if p and os.path.abspath(p) in g.canaries and ev.event_type in ("modified", "deleted", "moved"):
                            g.on_canary(p, ev.event_type)
                    if ev.event_type in ("modified", "created", "moved") and os.path.abspath(ev.src_path) not in g.canaries:
                        g.note_burst(ev.src_path)
                def on_modified(self, ev):
                    if ev.is_directory:
                        return
                    rel = os.path.relpath(ev.src_path, root)
                    chk, detail = detect.check_file(ev.src_path, rel, g.base.get(name, {}))
                    if chk:
                        g.on_flag(name, rel, chk, detail)
            return H()

        obs = Observer()
        for name, r in self.roots.items():
            obs.schedule(handler(name, r["path"]), r["path"], recursive=True)
        obs.start()
        print("GUARD_ON roots=%s debounce=%ss kill=%s contain=%s" % (
            list(self.roots), self.cfg["debounce_s"], self.cfg["kill"], self.cfg["contain"]), flush=True)
        try:
            while True:
                time.sleep(0.2)
                if time.time() - getattr(self, "_hb", 0) >= 1.0:
                    self._hb = time.time()
                    self.heartbeat()
                with self.lock:
                    ds, le = self.dirty_since, self.last_event
                if ds is None or vault.is_frozen():
                    continue
                now = time.time()
                if now - le >= self.cfg["debounce_s"] or now - ds >= self.cfg["max_wait_s"]:
                    with self.lock:
                        self.dirty_since = None
                    self.gated_commit()
        except KeyboardInterrupt:
            obs.stop()
        obs.join()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    g = Guard(load_config(sys.argv[1]))
    if not g.start():
        sys.exit(1)
    if "--once" in sys.argv:
        g.gated_commit("once")
    else:
        g.run()
