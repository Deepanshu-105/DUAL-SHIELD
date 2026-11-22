# v13.6 - new nodes (new laptops) can join the chain

On D (where the Fabric network runs):
    python3 network/add_node.py Mumbai 2        # NAME ORG(1|2)
It creates the Fabric identity Org2MSP:Mumbai@org2.example.com (signed by Org2's CA), approves it (owner, when governor threshold = 1;
otherwise a proposal is created - approve it in the dashboard Governance tab, then run the same command with --register) and stakes it.
It prints the number to use on the new laptop:  NODE_ID=6 (6, 7, 8 ... in the order added; kept in <network>/identities.json).
The dashboard shows the node by itself (Node cards, consensus, governance) once it is approved or staked.
The new laptop reports with:  NODE_ID=6 python3 network/chain_report.py <ip>   (or --who 6).  With GATEWAY_TLS=1 its client certificate needs CN=dualshield-node-Mumbai.
Restart the gateway once after unzipping (node fabric/gateway/server.js); the network itself is NOT reset.
Tested on a real Fabric network: add -> 6, repeat is idempotent, reportThreat from node 6 + node 1 -> K=2 confirmed.
No "Add node" web button on purpose: creating a certificate must stay a command on D.
