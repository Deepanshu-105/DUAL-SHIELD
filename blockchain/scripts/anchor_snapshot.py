import json, os, sys, time
from web3 import Web3

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEP = json.load(open(f"{HERE}/../deployments/localhost.json"))

w3 = Web3(Web3.HTTPProvider(os.environ.get("CHAIN_HTTP", "http://127.0.0.1:8545")))
contract = w3.eth.contract(address=DEP["address"], abi=DEP["abi"])

ip = sys.argv[1] if len(sys.argv) > 1 else "172.30.0.12"
root_hex = sys.argv[2]  # the real root from snapshot_latest.json, e.g. 89105032...
root_bytes32 = bytes.fromhex(root_hex)
t_attack = int(time.time())

account = w3.eth.accounts[0]  # must already be registered via registerNode()

tx = contract.functions.anchorCleanState(ip, root_bytes32, t_attack).transact({"from": account})
receipt = w3.eth.wait_for_transaction_receipt(tx)
print("tx hash:", receipt.transactionHash.hex())
print("gas used:", receipt.gasUsed)

root, t, anchored = contract.functions.getCleanState(ip).call()
print("on-chain root:", root.hex())
print("matches snapshot root:", root.hex() == root_hex)
print("tAttack:", t, "anchored:", anchored)
