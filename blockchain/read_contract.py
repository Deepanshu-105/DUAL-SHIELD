import json
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
address = json.load(open("deployed.json"))["address"]
abi = json.load(open("artifacts/contracts/Hello.sol/Hello.json"))["abi"]

contract = w3.eth.contract(address=address, abi=abi)
print("connected:", w3.is_connected())
print("message  :", contract.functions.message().call())
