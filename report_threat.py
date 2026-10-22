import json
from web3 import Web3

RPC_URL = "http://127.0.0.1:8545"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

with open("blockchain/artifacts/contracts/CityShield.sol/CityShield.json") as f:
    abi = json.load(f)["abi"]

w3 = Web3(Web3.HTTPProvider(RPC_URL))
print("connected:", w3.is_connected())

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)

# Hardhat's local account #0 (test-only, public key, do not use elsewhere)
account = w3.eth.accounts[1]

tx_hash = contract.functions.reportThreat("172.30.0.12", "hassh-abc123").transact({"from": account})
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print("tx hash:", receipt.transactionHash.hex())
print("gas used:", receipt.gasUsed)
print("report count:", contract.functions.reportCount("172.30.0.12").call())
print("confirmed:", contract.functions.isConfirmed("172.30.0.12").call())
