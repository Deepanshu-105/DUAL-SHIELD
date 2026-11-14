#!/usr/bin/env python3
"""Layer 1, network attacks beyond SSH: connection floods (DDoS), UDP floods, port scans, botnet floods.

Same pipeline as ssh_parser.py: detect -> block locally (ipset city_blacklist) -> report to the chain ->
K nodes agree -> every peer blocks. Only the DETECTOR is new. It runs as its own process, so the SSH parser
is not touched, and it is opt-in (FLOOD=1 in multi/config.env, or run it by hand).

  sudo python3 detector/flood_detector.py --iface eth0               # live, blocks + reports
  sudo python3 detector/flood_detector.py --iface eth0 --dry          # detect and print only
Environment: WHITELIST_EXTRA (comma list, like the parser), COREPORT=1 (lab: second report), NO_CHAIN=1,
             PYTHONPATH must contain network/ for chain_report (start_T.sh already sets it).

What it detects (limits are arguments, defaults suit a lab):
  syn-flood   one source sends >= --syn-rate new TCP connections per second (--window seconds average)
  udp-flood   one source sends >= --udp-rate UDP packets per second
  port-scan   one source touches >= --scan-ports different ports within --scan-window seconds
  botnet      total new-connection rate >= --total-rate AND >= --min-sources different sources: no single
              source is loud, so the top talkers are reported and "under attack mode" is announced
Honest limit: a flood that fills the network link cannot be stopped on the target. Blocking by IP also
fails against spoofed sources. This layer handles small and medium floods and shares the source fast.
"""
import argparse, collections, os, socket, struct, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os            # v10: Linux ipset/iptables or Windows Firewall
from netset import NetSet, from_env

IPSET_NAME = "city_blacklist"
FLOOD_LOG = shield_os.log_path("flood_block.log")
DEFAULT_WL = {"172.30.0.1", "172.30.0.11"}


class FloodAnalyzer:
    """Pure logic, no sockets: feed(ts, src, dport, proto, syn) -> list of (kind, ip, detail)."""

    def __init__(self, syn_rate=100, udp_rate=300, window=2.0, scan_ports=20, scan_window=10.0,
                 total_rate=400, min_sources=15, top_n=5, whitelist=(), cooldown=60.0):
        self.syn_rate, self.udp_rate, self.window = syn_rate, udp_rate, window
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.total_rate, self.min_sources, self.top_n = total_rate, min_sources, top_n
        self.whitelist, self.cooldown = NetSet(whitelist) | from_env(), cooldown
        self.syn = collections.defaultdict(collections.deque)      # src -> timestamps of new connections
        self.udp = collections.defaultdict(collections.deque)
        self.ports = collections.defaultdict(collections.deque)    # src -> (ts, port)
        self.all_syn = collections.deque()                         # (ts, src)
        self.flagged = {}                                          # src -> time flagged
        self.botnet_until = 0.0
        self.last_gc = 0.0

    def _trim(self, dq, now, span, key=lambda x: x):
        while dq and now - key(dq[0]) > span:
            dq.popleft()

    def _flag(self, out, now, kind, ip, detail):
        if ip in self.whitelist or now - self.flagged.get(ip, -1e9) < self.cooldown:
            return
        self.flagged[ip] = now
        out.append((kind, ip, detail))

    def feed(self, ts, src, dport, proto, syn=False):
        out = []
        if src in self.whitelist:
            return out
        if proto == "tcp" and syn:
            d = self.syn[src]
            d.append(ts)
            self._trim(d, ts, self.window)
            if len(d) / self.window >= self.syn_rate:
                self._flag(out, ts, "syn-flood", src, "%d new connections in %.0fs" % (len(d), self.window))
            self.all_syn.append((ts, src))
            self._trim(self.all_syn, ts, self.window, key=lambda x: x[0])
            self._botnet(out, ts)
        if proto == "udp":
            d = self.udp[src]
            d.append(ts)
            self._trim(d, ts, self.window)
            if len(d) / self.window >= self.udp_rate:
                self._flag(out, ts, "udp-flood", src, "%d packets in %.0fs" % (len(d), self.window))
        if (proto == "tcp" and syn) or proto == "udp":
            p = self.ports[src]
            p.append((ts, dport))
            self._trim(p, ts, self.scan_window, key=lambda x: x[0])
            distinct = len({x[1] for x in p})
            if distinct >= self.scan_ports:
                self._flag(out, ts, "port-scan", src, "%d different ports in %.0fs" % (distinct, self.scan_window))
        if ts - self.last_gc > 30:      # keep memory bounded
            self.last_gc = ts
            for tbl in (self.syn, self.udp, self.ports):
                for k in [k for k, v in tbl.items() if not v or ts - (v[-1][0] if isinstance(v[-1], tuple) else v[-1]) > 60]:
                    del tbl[k]
        return out

    def _botnet(self, out, now):
        n = len(self.all_syn)
        if n / self.window < self.total_rate or now < self.botnet_until:
            return
        counts = collections.Counter(s for _, s in self.all_syn)
        if len(counts) < self.min_sources:
            return                       # one or few loud sources: the per-source rule handles those
        self.botnet_until = now + self.cooldown
        out.append(("botnet", "*", "%d new connections/s from %d sources" % (n / self.window, len(counts))))
        for ip, c in counts.most_common(self.top_n):
            self._flag(out, now, "botnet", ip, "top talker: %d connections in %.0fs" % (c, self.window))


def parse_frame(buf):
    """Ethernet + IPv4 + TCP/UDP -> (src, dport, proto, syn) or None."""
    if len(buf) < 34:
        return None
    et = struct.unpack("!H", buf[12:14])[0]
    off = 14
    if et == 0x8100:
        et = struct.unpack("!H", buf[16:18])[0]
        off = 18
    if et != 0x0800:
        return None
    ihl = (buf[off] & 0x0F) * 4
    proto = buf[off + 9]
    src = socket.inet_ntoa(buf[off + 12:off + 16])
    t = off + ihl
    if proto == 6 and len(buf) >= t + 14:
        dport = struct.unpack("!H", buf[t + 2:t + 4])[0]
        flags = buf[t + 13]
        return src, dport, "tcp", bool(flags & 0x02) and not (flags & 0x10)
    if proto == 17 and len(buf) >= t + 4:
        return src, struct.unpack("!H", buf[t + 2:t + 4])[0], "udp", False
    return None


def mitigation_commands(rate=200):
    """'Under attack mode': cap NEW connections per source for everyone. Printed unless --apply."""
    return [["iptables", "-I", "INPUT", "1", "-p", "tcp", "--syn", "-m", "hashlimit", "--hashlimit-above",
             "%d/sec" % rate, "--hashlimit-mode", "srcip", "--hashlimit-name", "ds_syn", "-j", "DROP"]]


class Reactor:
    def __init__(self, dry, apply_mit, whitelist, chain, prefix="FLOOD_BLOCK", log=None, tag="FLOOD"):
        self.dry, self.apply_mit, self.chain = dry, apply_mit, chain
        self.whitelist = NetSet(whitelist) | from_env()
        self.prefix, self.log, self.tag = prefix, log or FLOOD_LOG, tag
        self.blocked = set()
        self.mitigated = False
        self.chain_report = None
        if chain:
            try:
                import chain_report
                self.chain_report = chain_report
            except Exception as e:
                print("[WARN] chain reporting off:", e, flush=True)

    def handle(self, kind, ip, detail):
        print("[%s] %s %s  %s" % (self.tag, kind, ip, detail), flush=True)
        if ip == "*":
            if not self.mitigated:
                self.mitigated = True
                for c in mitigation_commands():
                    if self.apply_mit and not self.dry:
                        subprocess.run(c, capture_output=True)
                    print("FLOOD_MITIGATION %s%s" % ("" if self.apply_mit and not self.dry else "(dry) ", " ".join(c)), flush=True)
            return
        if ip in self.whitelist or ip in self.blocked:
            return
        self.blocked.add(ip)
        if not self.dry:
            try:
                shield_os.block_add(ip)
            except shield_os.BlockError as e:
                print("[ERROR] block failed:", e.stderr, flush=True)
        line = "%s ip=%s ts=%.3f kind=%s" % (self.prefix, ip, time.time(), kind)
        print(line, flush=True)
        if not self.dry:
            try:
                with open(self.log, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass
        if self.chain_report and not self.dry:
            def run():
                try:
                    self.chain_report.report_to_chain(ip, kind, who=int(os.environ.get("NODE_ID", "1")))
                    if os.environ.get("COREPORT") == "1":     # DEMO ONLY, as in ssh_parser.py
                        self.chain_report.report_to_chain(ip, kind, who=2 if int(os.environ.get("NODE_ID", "1")) == 1 else 1)
                    print("[CHAIN] reported %s (%s)" % (ip, kind), flush=True)
                except Exception as e:
                    print("[WARN] chain report failed for %s: %s" % (ip, e), flush=True)
            threading.Thread(target=run, daemon=True).start()


def capture(iface, analyzer, reactor, stop=None):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if iface:
        s.bind((iface, 0))
    s.settimeout(0.5)
    while not (stop and stop.is_set()):
        try:
            buf = s.recv(2048)
        except socket.timeout:
            continue
        pk = parse_frame(buf)
        if pk:
            for ev in analyzer.feed(time.time(), *pk):
                reactor.handle(*ev)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface")
    ap.add_argument("--dry", action="store_true", help="detect and print only: no ipset, no chain")
    ap.add_argument("--apply-mitigation", action="store_true", help="really install the hashlimit rule in botnet mode")
    ap.add_argument("--syn-rate", type=float, default=100)
    ap.add_argument("--udp-rate", type=float, default=300)
    ap.add_argument("--window", type=float, default=2.0)
    ap.add_argument("--scan-ports", type=int, default=20)
    ap.add_argument("--scan-window", type=float, default=10.0)
    ap.add_argument("--total-rate", type=float, default=400)
    ap.add_argument("--min-sources", type=int, default=15)
    ap.add_argument("--whitelist", default=None, help="comma list; default = parser whitelist + WHITELIST_EXTRA + 127.0.0.1")
    a = ap.parse_args()
    if a.whitelist is None:
        wl = set(DEFAULT_WL) | {"127.0.0.1"} | {x.strip() for x in os.environ.get("WHITELIST_EXTRA", "").split(",") if x.strip()}
    else:
        wl = {x.strip() for x in a.whitelist.split(",") if x.strip()}
    an = FloodAnalyzer(a.syn_rate, a.udp_rate, a.window, a.scan_ports, a.scan_window, a.total_rate, a.min_sources, whitelist=wl)
    rx = Reactor(a.dry, a.apply_mitigation, wl, chain=os.environ.get("NO_CHAIN") != "1")
    print("FLOOD_DETECTOR on iface=%s dry=%s syn>=%g/s udp>=%g/s scan>=%d ports/%gs botnet>=%g/s from>=%d sources" % (
        a.iface or "all", a.dry, a.syn_rate, a.udp_rate, a.scan_ports, a.scan_window, a.total_rate, a.min_sources), flush=True)
    try:
        capture(a.iface, an, rx)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if shield_os.IS_WIN:
        sys.exit("flood_detector.py needs a raw packet socket (Linux). On Windows it is not available yet; the Windows target relies on the failed-logon watcher and the Windows Firewall.")
    main()
