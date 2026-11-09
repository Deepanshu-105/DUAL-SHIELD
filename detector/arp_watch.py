#!/usr/bin/env python3
"""ARP spoofing / man-in-the-middle detector (Layer 1, local network).

An ARP spoofer makes your machine believe the gateway (or another host) has the ATTACKER's hardware address.
This watches the neighbour table (`ip neigh show`) and flags:

  gateway-mac-changed   an IP you pinned (default: the default gateway) now has a different MAC
  mac-claims-many-ips   one MAC answers for two or more IPs, one of them pinned/gateway: the other IP is the spoofer
  mac-flapping          an IP changes MAC repeatedly within --flap-window seconds

Reaction: alert (ARP_ALERT line), optionally block the offending IP, optionally pin the real MAC with a
static ARP entry (--pin-static) so the poisoning stops working. Opt-in: ARP_WATCH=1.
  sudo python3 detector/arp_watch.py --dry
Limits: only sees ARP on the local network segment; a spoofer that keeps the real MAC for the gateway IP
(full impersonation) cannot be told apart. DNS spoofing and TLS interception are not covered.
"""
import argparse, collections, os, re, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os            # v10: Linux ipset/iptables or Windows Firewall
from flood_detector import Reactor

ARP_LOG = shield_os.log_path("arp_alert.log")
NEIGH = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})\s+(\S+)", re.I)


def parse_neigh(text):
    """`ip neigh show` text -> {ip: (mac, dev)} for entries that are not FAILED/INCOMPLETE."""
    out = {}
    for ln in text.splitlines():
        m = NEIGH.match(ln.strip())
        if m and m.group(4).upper() not in ("FAILED", "INCOMPLETE"):
            out[m.group(1)] = (m.group(3).lower(), m.group(2))
    return out


class ArpAnalyzer:
    def __init__(self, pinned=None, flap_window=60.0, flap_count=3, cooldown=300.0):
        self.pinned = dict(pinned or {})            # ip -> mac we trust (learned or given)
        self.flap_window, self.flap_count, self.cooldown = flap_window, flap_count, cooldown
        self.changes = collections.defaultdict(collections.deque)
        self.last = {}
        self.flagged = {}

    def _flag(self, out, now, kind, ip, detail, extra=None):
        if now - self.flagged.get((kind, ip), -1e9) < self.cooldown:
            return
        self.flagged[(kind, ip)] = now
        out.append((kind, ip, detail, extra))

    def feed(self, now, table, gateway=None):
        """table: {ip: (mac, dev)}. Returns [(kind, ip_to_act_on, detail, restore_cmd_or_None)]."""
        out = []
        if gateway and gateway in table and gateway not in self.pinned:
            self.pinned[gateway] = table[gateway][0]       # trust on first sight
        by_mac = collections.defaultdict(list)
        for ip, (mac, dev) in table.items():
            by_mac[mac].append(ip)
            if ip in self.last and self.last[ip] != mac:
                d = self.changes[ip]
                d.append(now)
                while d and now - d[0] > self.flap_window:
                    d.popleft()
                if len(d) >= self.flap_count:
                    self._flag(out, now, "mac-flapping", ip, "%s changed MAC %d times in %ds" % (ip, len(d), self.flap_window))
            self.last[ip] = mac
            want = self.pinned.get(ip)
            if want and want != mac:
                culprit = [x for x in by_mac.get(mac, []) if x != ip]
                self._flag(out, now, "gateway-mac-changed", ip, "%s moved from %s to %s" % (ip, want, mac),
                           "ip neigh replace %s lladdr %s dev %s nud permanent" % (ip, want, dev))
        for mac, ips in by_mac.items():
            if len(ips) >= 2:
                pins = [i for i in ips if self.pinned.get(i) and self.pinned[i] != mac]
                if pins:
                    for i in ips:
                        if i not in pins:
                            self._flag(out, now, "mac-claims-many-ips", i, "%s answers for %s too (MAC %s)" % (i, ",".join(pins), mac))
        return out


def default_gateway():
    r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--pin", action="append", default=[], help="ip=mac you trust (repeatable)")
    ap.add_argument("--pin-static", action="store_true", help="re-install the real MAC as a static ARP entry on attack")
    ap.add_argument("--every", type=float, default=2.0)
    a = ap.parse_args()
    wl = {x.strip() for x in os.environ.get("WHITELIST_EXTRA", "").split(",") if x.strip()}
    pinned = dict(p.split("=", 1) for p in a.pin)
    an = ArpAnalyzer({k: v.lower() for k, v in pinned.items()})
    rx = Reactor(a.dry, False, wl, chain=os.environ.get("NO_CHAIN") != "1", prefix="ARP_BLOCK", log=ARP_LOG, tag="ARP")
    gw = default_gateway()
    print("ARP_WATCH on gateway=%s dry=%s pinned=%s" % (gw, a.dry, list(pinned)), flush=True)
    while True:
        txt = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True).stdout
        for kind, ip, detail, fix in an.feed(time.time(), parse_neigh(txt), gw):
            if kind == "gateway-mac-changed":
                print("[ARP] %s  %s" % (kind, detail), flush=True)
                if fix and a.pin_static and not a.dry:
                    subprocess.run(fix.split(), capture_output=True)
                    print("ARP_PINNED", fix, flush=True)
                elif fix:
                    print("ARP_FIX_HINT", fix, flush=True)
            else:
                rx.handle(kind, ip, detail)
        time.sleep(a.every)


if __name__ == "__main__":
    if shield_os.IS_WIN:
        sys.exit("arp_watch.py reads `ip neigh` (Linux). Not available on Windows yet.")
    main()
