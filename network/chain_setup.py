#!/usr/bin/env python3
"""Node set-up on the Fabric chain (idempotent).
  chain_setup.py --approve        on D (owner): approve the node identities that may report (target, peer)
  chain_setup.py --register N     on T (N=1) or P (N=2): the node stakes itself in; needs the owner's approval first
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chainlib import Chain, ChainError, IDENTITY_NAMES

def main():
    c = Chain()
    a = sys.argv[1:]
    if a[:1] == ["--approve"]:
        for who in (1, 2):
            try:
                c.submit(0, "addNode", IDENTITY_NAMES[who]); print("approved", IDENTITY_NAMES[who])
            except ChainError as e:
                if "already" not in str(e): raise
                print("already approved", IDENTITY_NAMES[who])
    elif a[:1] == ["--register"] and len(a) == 2:
        who = int(a[1])
        for _ in range(30):                       # the owner may approve a moment later
            try:
                c.register_node(who); print("registered", IDENTITY_NAMES[who]); return
            except ChainError as e:
                if "already registered" in str(e): print("already registered"); return
                if "not approved" in str(e): time.sleep(2); continue
                raise
        sys.exit("FAIL: not approved by the owner (run multi/start_D.sh first)")
    else:
        sys.exit(__doc__)
main()
