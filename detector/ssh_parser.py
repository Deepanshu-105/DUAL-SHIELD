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

LOG_PATH = os.environ.get("LOG_PATH", "/var/log/auth.log")
IPSET_NAME = "city_blacklist"
THRESHOLD = 3   # failures ...
WINDOW = 5      # ... inside this many seconds

# Never block these: the SOC host (the Docker bridge gateway) and the peer node.
WHITELIST = {"172.30.0.1", "172.30.0.11"}

FAIL_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})"
)

fail_times = defaultdict(deque)
blocked_ips = set()
fingerprints = {}  # ip -> latest HASSH seen from that ip


# ---------------------------------------------------------------- firewall
def ensure_firewall():
    """Create the ipset and iptables rule if missing (both are lost on container restart)."""
    subprocess.run(["ipset", "create", IPSET_NAME, "hash:ip", "-exist"], check=True)
    rule = ["INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j", "DROP"]
    exists = subprocess.run(["iptables", "-C", *rule], capture_output=True).returncode == 0
    if not exists:
        subprocess.run(["iptables", "-I", *rule], check=True)


def tag(ip):
    """Text appended to log lines: the client fingerprint, if we have seen one."""
    h = fingerprints.get(ip)
    return f"  hassh={h}" if h else ""


def block_ip(ip):
    if ip in WHITELIST or ip in blocked_ips:
        return
    try:
        subprocess.run(["ipset", "add", IPSET_NAME, ip, "-exist"],
                       check=True, capture_output=True, text=True)
        blocked_ips.add(ip)
        print(f"[BLOCKED] {ip} added to {IPSET_NAME}{tag(ip)}", flush=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] could not add {ip}: {e.stderr.strip()}", flush=True)


# ---------------------------------------------------------------- detection
def record_failure(ip):
    if ip in WHITELIST:
        print(f"[SKIP] {ip} is whitelisted, failure not counted", flush=True)
        return
    now = time.time()
    times = fail_times[ip]
    times.append(now)
    while times and now - times[0] > WINDOW:  # keep only the last WINDOW seconds
        times.popleft()
    print(f"[FAIL] {ip} -> {len(times)} failure(s) in last {WINDOW}s{tag(ip)}", flush=True)
    if len(times) >= THRESHOLD:
        block_ip(ip)


def tail_log(path):
    """Follow a log file like `tail -f`, waiting for it to appear first."""
    while not os.path.exists(path):
        time.sleep(1)
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to the end: only new lines matter
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
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
        except OSError as e:  # includes PermissionError
            print(f"[WARN] HASSH sniffer is off: {e}", flush=True)

    threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------- main
def main():
    ensure_firewall()
    start_sniffer()
    print(f"Watching {LOG_PATH} for failed SSH logins...", flush=True)
    for line in tail_log(LOG_PATH):
        match = FAIL_PATTERN.search(line)
        if match:
            record_failure(match.group(1))


if __name__ == "__main__":
    main()
