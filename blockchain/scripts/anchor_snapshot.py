"""anchor_snapshot.py IP ROOT_HEX : record the clean-state Merkle root for IP on the Fabric ledger (anchorCleanState).
The anchoring identity (who=1, the target node) must be approved and staked; this script does that first if needed."""
import os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "network"))
from chainlib import Chain, ChainError, IDENTITY_NAMES

c = Chain()
ip = sys.argv[1] if len(sys.argv) > 1 else "172.30.0.12"
root_hex = sys.argv[2]                      # the real root from snapshot_latest.json
who = int(os.environ.get("ANCHOR_AS", "1"))

if c.query(0, "nodeInfo", IDENTITY_NAMES[who])["stake"] == 0:
    try:
        c.submit(0, "addNode", IDENTITY_NAMES[who])
    except ChainError:
        pass
    c.register_node(who)
c.anchor_clean_state(ip, root_hex, int(time.time()), who=who)
st = c.clean_state(ip)
print("on-chain root:", st["merkleRoot"])
print("matches snapshot root:", st["merkleRoot"] == root_hex.lower())
print("tAttack:", st["tAttack"], "anchored:", st["anchored"])
