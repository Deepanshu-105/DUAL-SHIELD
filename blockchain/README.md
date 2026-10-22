# How to connect to CityShield

Start chain:  cd blockchain && npx hardhat node --hostname 0.0.0.0
Deploy:       npx hardhat run scripts/deploy.js --network localhost
Shared file:  deployments/localhost.json  (address + ABI + URLs)

Event: ThreatConsensusReached(string ip, bytes32 ja3, uint count)
Read:  getTally(ip) -> (count, k, confirmed)
Accounts: Hardhat accounts[1]=A (target), [2]=B (peer), [3]=C. Unlocked, no keys needed.

## Fingerprint must be bytes32
Hash the string first (Python):
    from web3 import Web3
    ja3_bytes32 = Web3.keccak(text="hassh-abc123")
JavaScript: ethers.id("hassh-abc123")

## Python (M1), web3.py
    import json
    from web3 import Web3
    dep = json.load(open("deployments/localhost.json"))
    w3 = Web3(Web3.HTTPProvider("http://GATEWAY:8545"))
    c = w3.eth.contract(address=dep["address"], abi=dep["abi"])
    c.functions.reportThreat(ip, ja3_bytes32).transact({"from": w3.eth.accounts[2]})
    # listen: poll c.events.ThreatConsensusReached().get_logs(from_block=0)

## URLs
- From WSL itself: http://127.0.0.1:8545
- From a Docker container use the network gateway, not 127.0.0.1:
    docker network inspect smartcity-net | grep Gateway
    e.g. http://172.18.0.1:8545
- Dashboard in a Windows browser: http://127.0.0.1:8545

## Manual report (for M4's tally)
    IP=203.0.113.60 WHO=1 npx hardhat run scripts/send_report.js --network localhost
    IP=203.0.113.60 WHO=2 npx hardhat run scripts/send_report.js --network localhost
(Use WHO, not NODE: npx overwrites NODE.) Use a new IP each time.

## Second report (K=2)
The target alone can never reach consensus. The peer must also call
reportThreat for the same IP (from accounts[2]), or a script does.
