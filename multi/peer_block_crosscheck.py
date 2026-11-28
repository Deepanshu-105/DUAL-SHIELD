#!/usr/bin/env python3
"""P's own enforcement audit: does P's LOCAL firewall actually match what the CHAIN says is confirmed?
   Read-only on the chain (events/getTally) and read-only locally (ipset list via sudo -n). Writes nothing,
   changes nothing -- safe to run any time, including mid-demo.
   This catches real drift: e.g. a confirmed IP that P never actually blocked (a bug, or a laptop that
   missed the event), which a "PASS/FAIL on a screen" demo would otherwise hide.
   Usage:
       cd ~/DUAL-SHIELD
       bash -c '. multi/common.sh; PYTHONPATH=network python3 multi/peer_block_crosscheck.py'
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "network"))
try:
    from chainlib import Chain, ChainError
except ImportError:
    sys.exit("could not import chainlib -- run via: bash -c '. multi/common.sh; PYTHONPATH=network python3 multi/peer_block_crosscheck.py'")


def local_blocked_ips():
    try:
        r = subprocess.run(["sudo", "-n", "ipset", "list", "city_blacklist"], capture_output=True, text=True, timeout=5)
    except Exception as e:
        print("could not read ipset locally (%s) -- run with sudo rights, or as root" % e, file=sys.stderr)
        return set()
    ips = set()
    for line in r.stdout.splitlines():
        line = line.strip()
        if line and line[0].isdigit():
            ips.add(line.split()[0])
    return ips


def main():
    c = Chain()
    try:
        events, head = c.events(0, limit=1000)
    except ChainError as e:
        sys.exit("cannot reach the chain through the gateway: %s" % e)

    confirmed_ips = set()
    for e in events:
        if isinstance(e, dict) and e.get("name") in ("ThreatConsensusReached",):
            ip = e.get("ip")
            if ip:
                confirmed_ips.add(ip)

    local_ips = local_blocked_ips()

    print("Confirmed on-chain (ThreatConsensusReached): %s" % (confirmed_ips or "(none yet)"))
    print("Blocked locally on P (ipset city_blacklist):  %s" % (local_ips or "(none yet)"))
    print()

    missing = confirmed_ips - local_ips
    extra = local_ips - confirmed_ips
    if not confirmed_ips:
        print("VERDICT: no confirmed threats yet -- run an attack from A first, then run this again.")
    elif not missing and not extra:
        print("VERDICT: PASS -- every IP the chain confirmed is blocked here, and nothing extra is blocked.")
        print("         P's local enforcement matches the decentralized decision exactly.")
    else:
        if missing:
            print("VERDICT: MISMATCH -- chain confirmed %s but P never blocked it locally. Check that P's" % missing)
            print("         listener (network/listener.py) is running and reachable.")
        if extra:
            print("NOTE: P has %s blocked locally that the chain does not list as confirmed (could be an" % extra)
            print("      expired/cleared chain record, or a manual/earlier test block -- not necessarily a bug).")


if __name__ == "__main__":
    main()
