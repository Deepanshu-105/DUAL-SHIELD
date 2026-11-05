#!/usr/bin/env python3
"""Multi-signature governance of CityShield (v3). Talks to the chain like chain_report.py does.

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
--as N is the signer: an index into the chain's account list (the lab holds all keys; in a real
deployment each governor signs with their own key). --node takes an account index or an 0x address.
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipcrypt
from web3 import Web3

KINDS = {"overrule": 1, "protect": 2, "unprotect": 3, "add-node": 4, "revoke-node": 5, "add-governor": 6,
         "remove-governor": 7, "threshold": 8, "quorum": 9, "rate-limit": 10}
NAME = {v: k for k, v in KINDS.items()}
DEP = json.load(open(os.environ.get("DEPLOY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deployments", "localhost.json"))))
w3 = Web3(Web3.HTTPProvider(os.environ.get("CHAIN_HTTP", "http://127.0.0.1:8545")))
c = w3.eth.contract(address=Web3.to_checksum_address(DEP["address"]), abi=DEP["abi"])


def addr(x):
    if x is None:
        return "0x" + "0" * 40
    return w3.eth.accounts[int(x)] if str(x).isdigit() else Web3.to_checksum_address(x)


def send(fn, signer):
    tx = fn.transact({"from": w3.eth.accounts[signer]})
    r = w3.eth.wait_for_transaction_receipt(tx)
    return r


def show_proposal(i):
    kind, ip, node, value, approvals, executed = c.functions.getProposal(i).call()
    print("#%d %-15s ip=%-15s node=%s value=%s  signatures=%d/%d  %s" % (
        i, NAME.get(kind, kind), ip or "-", node[:8] if int(node, 16) else "-", value, approvals,
        c.functions.govThreshold().call(), "EXECUTED" if executed else "waiting"))


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
        print("governors: %s   threshold: %d of %d" % (
            [i for i in range(len(w3.eth.accounts)) if c.functions.governor(w3.eth.accounts[i]).call()],
            c.functions.govThreshold().call(), c.functions.govCount().call()))
        print("quorum: %s   report limit/hour: %s   required reports now: %d" % (
            c.functions.quorumPct().call() or "off (K=2)", c.functions.maxReportsPerHour().call() or "off", c.functions.required().call()))
        for i in range(c.functions.proposalCount().call()):
            show_proposal(i)
        return
    if a.cmd == "propose":
        if a.arg not in KINDS:
            sys.exit("kind must be one of: " + ", ".join(KINDS))
        r = send(c.functions.propose(KINDS[a.arg], ipcrypt.encode(a.ip) if a.ip else a.ip, addr(a.node), a.value), a.signer)
        print("proposal sent, gas", r.gasUsed)
        show_proposal(c.functions.proposalCount().call() - 1)
        return
    r = send(c.functions.approve(int(a.arg)), a.signer)
    print("signed, gas", r.gasUsed)
    show_proposal(int(a.arg))


if __name__ == "__main__":
    main()
