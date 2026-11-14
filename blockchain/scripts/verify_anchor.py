#!/usr/bin/env python3
"""verify_anchor.py IP FOLDER : recompute the Merkle root of FOLDER and compare it with the root
anchored on the Fabric ledger for IP (getCleanState). Prints ANCHOR_MATCH / ANCHOR_TAMPERED / ANCHOR_MISSING."""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "ransomware"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "network"))
import snapshot as snap   # same root rule as the anchored value
from chainlib import Chain

ip, folder = sys.argv[1], sys.argv[2]
local = snap.snapshot(folder)["root"]
st = Chain().clean_state(ip)
print("local root :", local)
print("chain root :", st["merkleRoot"], "anchored=%s" % st["anchored"])
if not st["anchored"]:
    print("ANCHOR_MISSING"); sys.exit(2)
if local == st["merkleRoot"]:
    print("ANCHOR_MATCH"); sys.exit(0)
print("ANCHOR_TAMPERED"); sys.exit(1)
