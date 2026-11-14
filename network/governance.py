#!/usr/bin/env python3
"""Multi-signature governance of CityShield (v3). Talks to the Fabric chaincode through the gateway like chain_report.py does.

Sensitive actions need M of N governors to sign. At start there is one governor (the deployer, account 0)
and threshold 1, so everything behaves as before. Typical set-up for the demo (3 governors, 2 must agree):

  python3 network/governance.py propose add-governor --node 4        # account 4 becomes a governor
  python3 network/governance.py propose add-governor --node 5
  python3 network/governance.py propose threshold --value 2          # from now on 2 of 3 must sign
  python3 network/governance.py propose overrule --ip 203.0.113.50 --as 0   # first signature
  python3 network/governance.py approve 3 --as 4                     # second signature: executes
  python3 network/governance.py status

Kinds: overrule, protect, unprotect, add-node, revoke-node, add-governor, remove-governor, threshold,
       quorum (percent, 0 = off), rate-limit (reports per node per hour, 0 = off).
--as N is the signer: a Fabric identity index (0 Org1 Admin, 1 Org1 User1, 2 Org2 User1, 3 Org1 User2, 4 Org2 User2,
5 Org2 Admin; the lab holds all keys, in a real deployment each governor signs with their own certificate).
--node takes an identity index or a full identity such as Org2MSP:Admin@org2.example.com.
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipcrypt
from chainlib import Chain, identity, IDENTITY_NAMES

KINDS = {"overrule": 1, "protect": 2, "unprotect": 3, "add-node": 4, "revoke-node": 5, "add-governor": 6,
         "remove-governor": 7, "threshold": 8, "quorum": 9, "rate-limit": 10}
NAME = {v: k for k, v in KINDS.items()}
chain = Chain()


def show_proposal(i, thr):
    p = chain.query(0, "getProposal", i)
    print("#%d %-15s ip=%-15s node=%s value=%s  signatures=%d/%d  %s" % (
        i, NAME.get(p["kind"], p["kind"]), p["ip"] or "-", p["node"] or "-", p["value"], p["approvals"], thr,
        "EXECUTED" if p["executed"] else "waiting"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["status", "propose", "approve"])
    ap.add_argument("arg", nargs="?", help="kind (propose) or proposal id (approve)")
    ap.add_argument("--ip", default="")
    ap.add_argument("--node")
    ap.add_argument("--value", type=int, default=0)
    ap.add_argument("--as", dest="signer", type=int, default=0)
    a = ap.parse_args()

    if a.cmd == "status":
        p = chain.params()
        govs = [i for i in IDENTITY_NAMES if chain.query(0, "nodeInfo", IDENTITY_NAMES[i])["governor"]]
        print("governors: %s   threshold: %d of %d" % (govs, p["govThreshold"], p["govCount"]))
        print("quorum: %s   report limit/hour: %s   required reports now: %d" % (p["quorumPct"] or "off (K=2)", p["maxReportsPerHour"] or "off", p["required"]))
        for i in range(chain.query(0, "proposalCount")):
            show_proposal(i, p["govThreshold"])
        return
    thr = chain.params()["govThreshold"]
    if a.cmd == "propose":
        if a.arg not in KINDS:
            sys.exit("kind must be one of: " + ", ".join(KINDS))
        chain.submit(a.signer, "propose", KINDS[a.arg], ipcrypt.encode(a.ip) if a.ip else "", identity(a.node), a.value)
        print("proposal sent")
        show_proposal(chain.query(0, "proposalCount") - 1, thr)
        return
    chain.submit(a.signer, "approve", int(a.arg))
    print("signed")
    show_proposal(int(a.arg), thr)


if __name__ == "__main__":
    main()
