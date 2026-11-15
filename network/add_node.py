#!/usr/bin/env python3
"""Add a new node (a new laptop) to the Dual-Shield chain.  Run on D.

   python3 network/add_node.py NAME ORG            e.g.  python3 network/add_node.py Mumbai 2
      1. creates the Fabric identity  Org<ORG>MSP:NAME@org<ORG>.example.com  (signed by that organisation's CA)  -> fabric/deploy/network.sh add-identity
      2. approves it: the owner does it directly when the governor threshold is 1; otherwise a proposal "Approve a node" is created and the
         governors approve it in the dashboard (Governance tab), then run this command again with --register
      3. registers it (stake) so that it may report threats

On the new laptop, report as this node with   NODE_ID=<number printed below>   (chain_report.py --who N). With GATEWAY_TLS=1 give it a certificate whose CN is
dualshield-node-NAME (multi/make_tls.sh). The dashboard shows the node automatically once it is approved or staked."""
import os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from chainlib import Chain, ChainError

args = [a for a in sys.argv[1:] if not a.startswith("--")]
if len(args) != 2 or args[1] not in ("1", "2"):
    sys.exit(__doc__)
name, org = args
c = Chain()
node = "Org%sMSP:%s@org%s.example.com" % (org, name, org)
ids = {i["node"]: i["who"] for i in c.identities()}
if node not in ids:
    if "--register" in sys.argv:
        sys.exit("identity %s does not exist yet: run without --register first" % node)
    net = os.path.join(HERE, "..", "fabric", "deploy", "network.sh")
    r = subprocess.run(["bash", net, "add-identity", org, name], capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
    if r.returncode != 0:
        sys.exit(1)
    ids = {i["node"]: i["who"] for i in c.identities()}
who = ids[node]
print("identity %s is number %d (use NODE_ID=%d on that laptop)" % (node, who, who))
info = c.query(0, "nodeInfo", node)
if not info["approved"]:
    p = c.params()
    if p["govThreshold"] == 1:
        c.submit(0, "addNode", node); print("approved by the owner")
    else:
        r = c.submit(0, "propose", 4, "", node, 0)
        print("governor threshold is %d: proposal created (%s). Approve it in the dashboard (Governance), then run:  python3 network/add_node.py %s %s --register" % (p["govThreshold"], r, name, org))
        sys.exit(0)
if info["stake"] == 0:
    try:
        c.register_node(who); print("registered with stake")
    except ChainError as e:
        sys.exit("could not register yet: %s" % e)
else:
    print("already staked")
print("NODE_READY %s who=%d" % (node, who))
