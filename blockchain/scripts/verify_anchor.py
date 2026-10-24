"""verify_anchor.py IP FOLDER : recompute the Merkle root of FOLDER and compare it with the root
anchored on-chain for IP (getCleanState). Prints ANCHOR_MATCH / ANCHOR_TAMPERED / ANCHOR_MISSING."""
import json, os, sys
from web3 import Web3

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "ransomware"))
import snapshot as snap   # same root rule as the anchored value

ip, folder = sys.argv[1], sys.argv[2]
dep = json.load(open(os.path.join(HERE, "..", "..", "deployments", "localhost.json")))
w3 = Web3(Web3.HTTPProvider(os.environ.get("CHAIN_HTTP", "http://127.0.0.1:8545")))
c = w3.eth.contract(address=dep["address"], abi=dep["abi"])

local = snap.snapshot(folder)["root"]
root, t_attack, anchored = c.functions.getCleanState(ip).call()
chain = root.hex()
print("local root :", local)
print("chain root :", chain, "anchored=%s" % anchored)
if not anchored:
    print("ANCHOR_MISSING"); sys.exit(2)
if local == chain:
    print("ANCHOR_MATCH"); sys.exit(0)
print("ANCHOR_TAMPERED"); sys.exit(1)
