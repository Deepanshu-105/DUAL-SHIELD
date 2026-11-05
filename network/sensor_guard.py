#!/usr/bin/env python3
"""False data injection / sensor spoofing detector (smart-city telemetry).

Smart-city decisions (traffic lights, air quality, water level) trust sensor readings. This guard checks every
reading before it is used and, when a sensor misbehaves, reports "sensor:<id>" to the same CityShield chain.
K nodes agree -> every peer records SENSOR_QUARANTINE and stops trusting that sensor (same consensus as IP blocks).

Checks per reading  {"id","type","value","ts","seq","group","sig"}:
  forged-reading   HMAC-SHA256 signature missing or wrong (per-sensor key = HMAC(master, id)); needs --secret
  replay           sequence number or timestamp not newer than the last one from that sensor
  out-of-range     value outside the physical min/max for that sensor type
  impossible-jump  changes faster than the type allows (max_step_per_s)
  stuck-value      exactly the same value stuck_n times in a row (frozen or replayed sensor)
  neighbour-outlier far from the median of the other sensors in its group (needs >= 3 in the group)

  python3 network/sensor_guard.py --demo                       # simulated city, attacks injected, prints alerts
  cat readings.jsonl | python3 network/sensor_guard.py --stdin --secret KEY
  python3 network/sensor_guard.py --udp 9999 --secret KEY      # gateways send one JSON reading per datagram
Honest limits: an attacker who holds a sensor's key and fakes plausible values that agree with its neighbours is
not caught; many sensors compromised together defeat the neighbour check. Needs the physical limits to be set sensibly.
"""
import argparse, collections, hashlib, hmac, json, os, random, socket, statistics, sys, threading, time

SPECS = {   # physical limits; change to match your sensors
    "temp_c":   {"min": -30, "max": 60, "max_step_per_s": 2.0, "stuck_n": 10, "max_dev": 8.0},
    "pm25":     {"min": 0, "max": 1000, "max_step_per_s": 80.0, "stuck_n": 10, "max_dev": 120.0},
    "water_cm": {"min": 0, "max": 600, "max_step_per_s": 5.0, "stuck_n": 12, "max_dev": 40.0},
    "traffic_vph": {"min": 0, "max": 3000, "max_step_per_s": 300.0, "stuck_n": 10, "max_dev": 800.0},
}
ALERT_LOG = "/var/log/sensor_alert.log"


def sensor_key(master, sid):
    return hmac.new(master.encode(), sid.encode(), hashlib.sha256).digest()


def sign(master, r):
    msg = "%s|%s|%s|%s|%s" % (r["id"], r["type"], r["value"], r["ts"], r.get("seq", ""))
    return hmac.new(sensor_key(master, r["id"]), msg.encode(), hashlib.sha256).hexdigest()


class SensorGuard:
    def __init__(self, specs=None, secret=None, cooldown=300.0, group_window=60.0):
        self.specs, self.secret, self.cooldown, self.group_window = specs or SPECS, secret, cooldown, group_window
        self.last = {}                                  # id -> (ts, value, seq)
        self.same = collections.defaultdict(int)        # id -> consecutive identical values
        self.groups = collections.defaultdict(dict)     # group -> {id: (ts, value)}
        self.flagged = {}
        self.quarantined = set()

    def _flag(self, out, now, kind, sid, detail):
        if now - self.flagged.get((kind, sid), -1e9) < self.cooldown:
            return
        self.flagged[(kind, sid)] = now
        out.append((kind, sid, detail))

    def feed(self, r, now=None):
        """r: dict reading. Returns [(kind, sensor_id, detail)]. Bad readings are NOT stored as trusted state."""
        now = now if now is not None else r.get("ts", time.time())
        out = []
        sid, typ, val = r.get("id"), r.get("type"), r.get("value")
        spec = self.specs.get(typ)
        if sid is None or spec is None or not isinstance(val, (int, float)):
            return [("malformed", str(sid), "unknown type or non-numeric value")]
        if self.secret and not hmac.compare_digest(str(r.get("sig", "")), sign(self.secret, r)):
            self._flag(out, now, "forged-reading", sid, "bad or missing signature")
            return out
        ts, seq = r.get("ts", now), r.get("seq")
        prev = self.last.get(sid)
        if prev:
            pts, pval, pseq = prev
            if (seq is not None and pseq is not None and seq <= pseq) or ts < pts:
                self._flag(out, now, "replay", sid, "seq/time not newer (seq %s <= %s)" % (seq, pseq))
                return out
        bad = False
        if not (spec["min"] <= val <= spec["max"]):
            self._flag(out, now, "out-of-range", sid, "%s=%s outside [%s, %s]" % (typ, val, spec["min"], spec["max"]))
            bad = True
        if prev and not bad:
            dt = max(ts - prev[0], 0.001)
            if abs(val - prev[1]) / dt > spec["max_step_per_s"]:
                self._flag(out, now, "impossible-jump", sid, "%s -> %s in %.1fs" % (prev[1], val, dt))
                bad = True
        if prev and val == prev[1]:
            self.same[sid] += 1
            if spec.get("stuck_n") and self.same[sid] >= spec["stuck_n"]:
                self._flag(out, now, "stuck-value", sid, "same value %s %d times" % (val, self.same[sid] + 1))
        else:
            self.same[sid] = 0
        g = r.get("group")
        if g and not bad:
            gd = self.groups[g]
            for k in [k for k, (t, _) in gd.items() if now - t > self.group_window]:
                del gd[k]
            others = [v for k, (t, v) in gd.items() if k != sid and k not in self.quarantined]
            if len(others) >= 3:
                med = statistics.median(others)
                if abs(val - med) > spec["max_dev"]:
                    self._flag(out, now, "neighbour-outlier", sid, "%s vs neighbours' median %s" % (val, med))
                    bad = True
            if not bad:
                gd[sid] = (now, val)
        if not bad:
            self.last[sid] = (ts, val, seq)
        if out:
            self.quarantined.add(sid)
        return out


class Reaction:
    def __init__(self, dry, chain=True):
        self.dry, self.cr = dry, None
        if chain and not dry:
            try:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                import chain_report
                self.cr = chain_report
            except Exception as e:
                print("[WARN] chain reporting off:", e, flush=True)

    def handle(self, kind, sid, detail):
        line = "SENSOR_ALERT id=%s ts=%.3f kind=%s" % (sid, time.time(), kind)
        print("[SENSOR] %s %s  %s" % (kind, sid, detail), flush=True)
        print(line, flush=True)
        if not self.dry:
            try:
                open(ALERT_LOG, "a").write(line + "\n")
            except OSError:
                pass
        if self.cr:
            def run():
                try:
                    self.cr.report_to_chain("sensor:" + sid, kind, who=1)
                    if os.environ.get("COREPORT") == "1":         # DEMO ONLY, as in ssh_parser.py
                        self.cr.report_to_chain("sensor:" + sid, kind, who=2)
                    print("[CHAIN] reported sensor:%s" % sid, flush=True)
                except Exception as e:
                    print("[WARN] chain report failed:", e, flush=True)
            threading.Thread(target=run, daemon=True).start()


def demo(guard, rx):
    """A small simulated district: 6 temperature sensors, then four different attacks."""
    random.seed(3)
    seq = collections.defaultdict(int)
    t0 = 1000.0
    def reading(i, t, v, **kw):
        seq[i] += 1
        r = {"id": "temp-%d" % i, "type": "temp_c", "value": v, "ts": t0 + t, "seq": seq[i], "group": "district-7"}
        r.update(kw)
        if guard.secret and "sig" not in kw:
            r["sig"] = sign(guard.secret, r)
        return r
    for t in range(0, 60, 2):
        for i in range(1, 7):
            v = 27 + random.uniform(-0.4, 0.4)
            if t >= 12 and i == 3:
                v = 27 + (t - 10) * 1.5                       # attack 1: slow drift (each step looks legal), far from neighbours
            if t >= 24 and i == 4:
                v = 27.0                                      # attack 2: frozen sensor
            if t == 30 and i == 5:
                v = -80.0                                     # attack 3: impossible value
            for ev in guard.feed(reading(i, t, round(v, 2))):
                rx.handle(*ev)
    r = reading(6, 60, 27.1)                                  # attack 4: replay of an old message
    r["seq"] = 3
    if guard.secret:
        r["sig"] = sign(guard.secret, r)
    for ev in guard.feed(r):
        rx.handle(*ev)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--udp", type=int)
    ap.add_argument("--secret", default=os.environ.get("SENSOR_SECRET"))
    ap.add_argument("--dry", action="store_true", help="print only: no log file, no chain")
    a = ap.parse_args()
    g, rx = SensorGuard(secret=a.secret), Reaction(a.dry or a.demo and os.environ.get("NO_CHAIN") == "1")
    if a.demo:
        return demo(g, rx)
    if a.udp:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", a.udp))
        print("SENSOR_GUARD listening on udp/%d signed=%s" % (a.udp, bool(a.secret)), flush=True)
        while True:
            data, _ = s.recvfrom(4096)
            try:
                for ev in g.feed(json.loads(data)):
                    rx.handle(*ev)
            except ValueError:
                print("[SENSOR] malformed datagram", flush=True)
    for ln in sys.stdin:
        if ln.strip():
            for ev in g.feed(json.loads(ln)):
                rx.handle(*ev)


if __name__ == "__main__":
    main()
