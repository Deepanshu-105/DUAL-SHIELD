#!/usr/bin/env python3
"""SSH brute-force parser, version 2.

Watches the sshd log. 3 failed logins from one IP inside 5 seconds puts that IP
into the `city_blacklist` ipset, where an iptables rule drops all its traffic.

New in version 2:
  * a whitelist: trusted IPs are never counted or blocked
  * HASSH: every connection's SSH client fingerprint is captured and printed
    next to the [FAIL] and [BLOCKED] lines (see hassh.py)
  * waits for auth.log instead of crashing when the file does not exist yet
"""
import os
import re
import subprocess
import threading
import time
from collections import defaultdict, deque

import hassh
import sys

sys.path.insert(0, "/opt/shield")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os            # v10: Linux ipset/iptables or Windows Firewall
try:
    import chain_report  # M1: reports blocks to the CityShield contract
except Exception as e:
    chain_report = None
    print(f"[WARN] chain reporting is off: {e}", flush=True)

NODE_ID = int(os.environ.get("NODE_ID", "1"))   # v11: 1 = target node, 2 = peer node (a peer that also runs this parser is a real second reporter)
LOG_PATH = os.environ.get("LOG_PATH") or shield_os.log_path("auth.log")   # Windows: written by win_logon_watch.py
IPSET_NAME = "city_blacklist"
PARSER_LOG = os.environ.get("PARSER_LOG") or shield_os.log_path("parser_block.log")
THRESHOLD = 3   # failures ...
WINDOW = 5      # ... inside this many seconds

# Never block these: the SOC host (the Docker bridge gateway) and the peer node.
WHITELIST = {"172.30.0.1", "172.30.0.11", "::1", "127.0.0.1"}
# Four-laptop mode: the dashboard and peer laptops are added through WHITELIST_EXTRA="ip1,ip2".
WHITELIST |= {x.strip() for x in os.environ.get("WHITELIST_EXTRA", "").split(",") if x.strip()}

# Optional: whole networks that must never be blocked (shared campus/mobile NAT), e.g. WHITELIST_CIDRS="10.0.0.0/8,192.168.0.0/16"
try:
    import ipaddress as _ipa
    _NEVER_NETS = [_ipa.ip_network(x.strip(), strict=False) for x in os.environ.get("WHITELIST_CIDRS", "").split(",") if x.strip()]
except ValueError:
    _NEVER_NETS = []


def _never_block(ip):
    if not _NEVER_NETS:
        return False
    a = _ipa.ip_address(ip)
    return any(a in n for n in _NEVER_NETS)


FAIL_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7})"
)

fail_times = defaultdict(deque)
blocked_ips = set()
fingerprints = {}  # ip -> latest HASSH seen from that ip


# ---------------------------------------------------------------- firewall
def ensure_firewall():
    """Create the ipset and iptables rule if missing (both are lost on container restart)."""
    shield_os.block_init()


_HERE = os.path.dirname(os.path.abspath(__file__))
TOR_FILES = [os.environ.get("TOR_LIST", os.path.join(_HERE, "tor_exit_nodes.txt")),
             os.environ.get("TOR_LIST_EXTRA", os.path.join(_HERE, "tor_lab_test.txt"))]
# HASSH value your own lab captured from Hydra. Not a public list.
BAD_HASSH = set(filter(None, os.environ.get(
    "BAD_HASSH", "015322ee8471fa8338c558a918183b11").split(",")))
METRICS = os.environ.get("METRICS_LOG") or shield_os.log_path("metrics.log")
tor_ips = set()


def load_tor():
    for path in TOR_FILES:
        try:
            with open(path) as f:
                tor_ips.update(l.strip() for l in f if l.strip() and not l.startswith("#"))
        except OSError as e:
            print(f"[WARN] Tor list {path} not loaded: {e}", flush=True)
    print(f"[TOR] {len(tor_ips)} addresses loaded", flush=True)


def metric(name, ms):
    line = f"METRIC {name}={ms:.3f}"
    print(line, flush=True)
    with open(METRICS, "a") as f:
        f.write(line + "\n")


def tag(ip):
    """Text appended to log lines: the client fingerprint, if we have seen one."""
    h = fingerprints.get(ip)
    extra = "  tor=yes" if ip in tor_ips else ""
    return (f"  hassh={h}" if h else "") + extra


def report_async(ip):
    """Send the block to the chain in a background thread so log tailing never stalls."""
    if chain_report is None:
        return

    def run():
        try:
            fp = fingerprints.get(ip, "no-hassh")
            if ":" in ip:                           # IPv6 is blocked locally; the chain record format is IPv4 only
                print(f"[CHAIN] {ip}: IPv6, not shared on the chain", flush=True)
                return
            chain_report.report_to_chain(ip, fp, who=NODE_ID)       # T is node 1, P is node 2 (each reports what IT saw)
            if os.environ.get("COREPORT") == "1":  # DEMO ONLY (GATEWAY_LAB=1): one laptop stands in for the peer's report
                chain_report.report_to_chain(ip, fp, who=2 if NODE_ID == 1 else 1)
            print(f"[CHAIN] reported {ip}", flush=True)
        except Exception as e:
            print(f"[WARN] chain report failed for {ip}: {e}", flush=True)

    threading.Thread(target=run, daemon=True).start()


def block_ip(ip, t_detect=None):
    if ip in WHITELIST or ip in blocked_ips:
        return
    try:
        shield_os.block_add(ip)
        blocked_ips.add(ip)
        if t_detect is not None:
            metric("drop_ms", (time.perf_counter() - t_detect) * 1000)
        t1 = time.perf_counter()
        is_tor = ip in tor_ips
        bad_tool = fingerprints.get(ip) in BAD_HASSH
        metric("lookup_ms", (time.perf_counter() - t1) * 1000)
        if is_tor or bad_tool:
            print(f"[PROFILE] {ip} tor={is_tor} known_attack_tool={bad_tool}", flush=True)
        print(f"[BLOCKED] {ip} added to {IPSET_NAME}{tag(ip)}", flush=True)
        ts = time.time()
        line = f"PARSER_BLOCK ip={ip} ts={ts:.3f}"
        print(f"[{line.split()[0]}] {line}", flush=True)
        with open(PARSER_LOG, "a") as f:
            f.write(line + "\n")
        report_async(ip)
    except shield_os.BlockError as e:
        print(f"[ERROR] could not add {ip}: {e.stderr.strip()}", flush=True)


# ---------------------------------------------------------------- detection
def record_failure(ip):
    if ip in WHITELIST or _never_block(ip):
        print(f"[SKIP] {ip} is whitelisted, failure not counted", flush=True)
        return
    now = time.time()
    times = fail_times[ip]
    times.append(now)
    while times and now - times[0] > WINDOW:  # keep only the last WINDOW seconds
        times.popleft()
    print(f"[FAIL] {ip} -> {len(times)} failure(s) in last {WINDOW}s{tag(ip)}", flush=True)
    if len(times) >= THRESHOLD:
        block_ip(ip, time.perf_counter())


def tail_log(path):
    """Follow a log file like `tail -f`, waiting for it to appear first."""
    while not os.path.exists(path):
        time.sleep(1)
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to the end: only new lines matter
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.02)
                continue
            yield line


# ---------------------------------------------------------------- HASSH
def on_hassh(ip, value, _algorithms):
    fingerprints[ip] = value
    print(f"[HASSH] {ip} -> {value}", flush=True)


def start_sniffer():
    def run():
        try:
            hassh.sniff(on_hassh)
        except (OSError, AttributeError) as e:  # PermissionError; no raw packet socket on Windows
            print(f"[WARN] HASSH sniffer is off: {e}", flush=True)

    threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------- main
def main():
    ensure_firewall()
    start_sniffer()
    load_tor()
    print(f"Watching {LOG_PATH} for failed SSH logins...", flush=True)
    for line in tail_log(LOG_PATH):
        match = FAIL_PATTERN.search(line)
        if match:
            record_failure(match.group(1))


if __name__ == "__main__":
    main()
