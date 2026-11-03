#!/usr/bin/env python3
"""Block expiry for the city_blacklist ipset (v3). A false positive should not lock an address out forever.

Reads the block logs the detectors already write (PARSER_BLOCK / PEER_BLOCK / FLOOD_BLOCK lines with ts=),
and removes entries older than TTL seconds. Opt-in: nothing changes unless you run it. It never touches the
set's creation options, so the existing ipset and iptables rule keep working.

  python3 detector/expire_blocks.py --ttl 3600                 # loop forever (run as root)
  python3 detector/expire_blocks.py --ttl 3600 --once --dry    # show what would be removed
"""
import argparse, re, subprocess, sys, time

LOGS = ["/var/log/parser_block.log", "/var/log/peer_block.log", "/var/log/flood_block.log"]
LINE = re.compile(r"^(?:PARSER_BLOCK|PEER_BLOCK|FLOOD_BLOCK) ip=(\S+) ts=([\d.]+)")
UNBLOCK = re.compile(r"^PEER_UNBLOCK ip=(\S+) ts=([\d.]+)")


def latest_block_times(paths):
    """ip -> time of its most recent block, ignoring IPs whose last event was an unblock."""
    last = {}
    for p in paths:
        try:
            lines = open(p, errors="replace").read().splitlines()
        except OSError:
            continue
        for ln in lines:
            m = LINE.match(ln)
            if m:
                last[m.group(1)] = max(last.get(m.group(1), 0), float(m.group(2)))
                continue
            m = UNBLOCK.match(ln)
            if m:
                last.pop(m.group(1), None)
    return last


def expired(last, ttl, now=None):
    now = now or time.time()
    return sorted(ip for ip, t in last.items() if now - t > ttl)


def sweep(ttl, paths, dry=False, setname="city_blacklist"):
    gone = []
    for ip in expired(latest_block_times(paths), ttl):
        if dry:
            print("EXPIRE_DRY_RUN would remove", ip, flush=True)
        else:
            r = subprocess.run(["ipset", "del", setname, ip, "-exist"], capture_output=True, text=True)
            if r.returncode == 0:
                print("EXPIRED ip=%s ts=%.3f" % (ip, time.time()), flush=True)
                with open("/var/log/peer_block.log", "a") as f:
                    f.write("PEER_UNBLOCK ip=%s ts=%.3f reason=expired\n" % (ip, time.time()))
        gone.append(ip)
    return gone


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--log", action="append", default=[])
    a = ap.parse_args()
    paths = a.log or LOGS
    while True:
        sweep(a.ttl, paths, a.dry)
        if a.once:
            break
        time.sleep(30)
