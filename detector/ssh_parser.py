#!/usr/bin/env python3
"""
Phase 2: Ingress alert.
Tails /var/log/auth.log inside the target container, extracts failed SSH
logins, and blocks an IP via ipset once it fails 3 times within 5 seconds.
"""

import re
import subprocess
import time
from collections import defaultdict, deque

LOG_PATH = "/var/log/auth.log"
FAIL_PATTERN = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)")
WINDOW_SECONDS = 5
THRESHOLD = 3
BLACKLIST_SET = "city_blacklist"

# ip -> deque of timestamps (seconds since epoch) of recent failures
fail_times = defaultdict(deque)
blocked_ips = set()


def block_ip(ip: str) -> None:
    if ip in blocked_ips:
        return
    try:
        subprocess.run(
            ["ipset", "add", BLACKLIST_SET, ip],
            check=True,
            capture_output=True,
            text=True,
        )
        blocked_ips.add(ip)
        print(f"[BLOCKED] {ip} added to {BLACKLIST_SET}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] could not add {ip}: {e.stderr.strip()}")


def record_failure(ip: str) -> None:
    now = time.time()
    times = fail_times[ip]
    times.append(now)

    # drop timestamps older than the window
    while times and now - times[0] > WINDOW_SECONDS:
        times.popleft()

    print(f"[FAIL] {ip} -> {len(times)} failure(s) in last {WINDOW_SECONDS}s")

    if len(times) >= THRESHOLD:
        block_ip(ip)


def tail_log(path: str):
    """Follow a log file like `tail -f`, yielding new lines as they appear."""
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to end, only watch new lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def ensure_firewall():
    """Create the ipset and iptables rule if they don't exist (lost on container restart)."""
    subprocess.run(["ipset", "create", "city_blacklist", "hash:ip", "-exist"], check=True)
    rule = ["INPUT", "-m", "set", "--match-set", "city_blacklist", "src", "-j", "DROP"]
    exists = subprocess.run(["iptables", "-C", *rule], capture_output=True).returncode == 0
    if not exists:
        subprocess.run(["iptables", "-I", *rule], check=True)

def main():
    ensure_firewall()
    print(f"Watching {LOG_PATH} for failed SSH logins...")
    for line in tail_log(LOG_PATH):
        match = FAIL_PATTERN.search(line)
        if match:
            record_failure(match.group(1))


if __name__ == "__main__":
    main()


