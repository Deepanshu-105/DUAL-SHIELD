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
            "release_after_s": 60.0, "kill": True, "contain": "dry", "allow": []}


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

    # ---- baseline / commit -------------------------------------------------
    def _rebuild_baselines(self):
        for name in self.roots:
            d = os.path.join(vault.VAULT, "files", name)
            self.base[name] = detect.build_baseline(d) if os.path.isdir(d) else {}

    def start(self):
        os.makedirs("evidence", exist_ok=True)
        if not os.path.isdir(os.path.join(vault.VAULT, ".git")):
            vault.init(self.cfg["roots"][0]["path"])
        if vault.is_frozen():
            print("GUARD_FROZEN vault is frozen; restore then run: python3 vault.py unfreeze")
            return False
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

    def on_flag(self, name, rel, chk, detail):
        print("%.3f FLAGGED [check %s] %s/%s  %s" % (time.time(), chk, name, rel, detail), flush=True)
        rule = self.rules.get(name)
        if rule:
            before = rule.cooldown_until
            rule.on_flag(rel)
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
