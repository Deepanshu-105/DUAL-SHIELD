#!/usr/bin/env python3
"""P's own consensus-integrity check (read-only chain QUERY, never writes anything to the chain).
   Run ONLY on P, any time after D and P are both READY. It asks the chain directly -- not D, not T --
   "who actually confirmed this threat?" and prints the distinct reporter node IDs. This is the proof that
   K=2 is a REAL two-party agreement (two different node IDs), not one laptop confirming itself twice.
   Usage:  python3 multi/peer_verify_consensus.py [IP]      (IP defaults to $T_IP from multi/config.env)
   Run it like this (sources multi/common.sh first, so TLS / gateway settings are picked up the same way
   start_T.sh / start_P.sh use them):
       cd ~/DUAL-SHIELD
       bash -c '. multi/common.sh; PYTHONPATH=network python3 multi/peer_verify_consensus.py'
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "network"))
try:
    from chainlib import Chain, ChainError
except ImportError:
    sys.exit("could not import chainlib -- run this with PYTHONPATH=network (see the usage note at the top of this file)")


def main():
    ip = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("T_IP")
    if not ip:
        sys.exit("no IP given and T_IP is not set -- run via: bash -c '. multi/common.sh; PYTHONPATH=network python3 multi/peer_verify_consensus.py'")

    c = Chain()
    try:
        params = c.params()
    except ChainError as e:
        sys.exit("cannot reach the chain through the gateway: %s" % e)

    print("Chain consensus parameters:", params)
    print()

    try:
        tally = c.query(0, "getTally", ip)
    except ChainError as e:
        sys.exit("getTally failed for %s: %s" % (ip, e))

    reporters = tally.get("reporters", [])
    distinct = sorted(set(reporters))
    k = tally.get("k")
    confirmed = tally.get("confirmed")

    print("Target IP:        %s" % ip)
    print("Report count:      %s" % tally.get("count"))
    print("Required (K):      %s" % k)
    print("All reports from:  %s" % (reporters or "(none yet)"))
    print("Distinct reporters:%s" % (distinct or "(none yet)"))
    print("Confirmed:         %s" % confirmed)
    print()

    if not reporters:
        print("VERDICT: no reports yet for this IP -- run an attack from A first, then run this again.")
    elif confirmed and len(distinct) >= 2:
        print("VERDICT: PASS -- %d DIFFERENT node IDs independently reported this IP. This is a genuine" % len(distinct))
        print("         two-party confirmation, verified directly from the chain by P, not taken on trust.")
    elif confirmed and len(distinct) < 2:
        print("VERDICT: WARNING -- confirmed, but all reports trace to the SAME node ID (%s)." % distinct)
        print("         This is the lab shortcut (one laptop reporting as both organisations). Set")
        print("         PEER_DETECT=1 in multi/config.env and restart P for a real second reporter.")
    else:
        print("VERDICT: not confirmed yet (%s of %s reports so far)." % (tally.get("count"), k))


if __name__ == "__main__":
    main()
