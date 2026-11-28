#!/usr/bin/env python3
"""P's own identity, stake and governance standing on the chain (read-only query, no writes).
   Proves P is a genuine, registered, staked participant -- its vote carries real weight and real
   stake that can be forfeited (slashed) if it misbehaves, not a dummy node that just clicks "confirm".
   Usage:
       cd ~/DUAL-SHIELD
       bash -c '. multi/common.sh; PYTHONPATH=network python3 multi/peer_identity_status.py [NODE_ID]'
   NODE_ID defaults to 2 (P's usual node id in this lab).
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "network"))
try:
    from chainlib import Chain, ChainError
except ImportError:
    sys.exit("could not import chainlib -- run via: bash -c '. multi/common.sh; PYTHONPATH=network python3 multi/peer_identity_status.py'")


def main():
    node = sys.argv[1] if len(sys.argv) > 1 else "2"
    c = Chain()
    try:
        params = c.query(0, "params")
        info = c.query(0, "nodeInfo", node)
    except ChainError as e:
        sys.exit("cannot reach the chain through the gateway: %s" % e)

    print("Chain-wide parameters:")
    for k in ("K", "STAKE", "WINDOW", "nodeCount", "govCount", "govThreshold", "quorumPct", "minOrgs", "slashedPool", "required"):
        if k in params:
            print("  %-14s %s" % (k, params[k]))
    print()
    print("P's own identity (node %s):" % node)
    print("  approved:  %s" % info.get("approved"))
    print("  stake:     %s" % info.get("stake"))
    print("  governor:  %s" % info.get("governor"))
    print()

    if not info.get("approved"):
        print("VERDICT: this node is NOT currently approved -- its reports would not count toward K. Check")
        print("         registration (network/chain_setup.py --register) and the NODE_ID used when starting P.")
    elif not info.get("stake"):
        print("VERDICT: approved but stake shows 0 -- either it was already slashed, or staking is informational")
        print("         only in this build. Either way, confirm with the team what STAKE in 'params' means here.")
    else:
        print("VERDICT: P is a real, approved, staked participant (stake=%s). If P reported something false," % info.get("stake"))
        print("         governance can overrule it and this stake is forfeited (see cityshield.js: NodeSlashed).")
        print("         This is the economic reason P's vote cannot be ignored or faked.")


if __name__ == "__main__":
    main()
