import ipaddress, json, os, subprocess, sys, time
from web3 import Web3

DEP = json.load(open(os.environ.get("DEPLOY", "/opt/shield/localhost.json")))
w3 = Web3(Web3.HTTPProvider(os.environ.get("CHAIN_HTTP", "http://host.docker.internal:8545")))
c = w3.eth.contract(address=Web3.to_checksum_address(DEP["address"]), abi=DEP["abi"])

def report_to_chain(ip, fingerprint="manual", who=1):
    """Call this from detector/ssh_parser.py right after its ipset add."""
    tx = c.functions.reportThreat(ip, Web3.keccak(text=fingerprint)).transact(
        {"from": w3.eth.accounts[who]})
    w3.eth.wait_for_transaction_receipt(tx)

if __name__ == "__main__":
    ip = sys.argv[1]
    ipaddress.ip_address(ip)
    if "--block" in sys.argv:
        subprocess.run(["ipset", "add", "city_blacklist", ip, "-exist"], check=True)
        print("TARGET_BLOCK ip=%s ts=%.3f" % (ip, time.time()), flush=True)
    report_to_chain(ip, "test-fingerprint", who=1)
    if os.environ.get("COREPORT") == "1":
        # DEMO ONLY: stands in for the peer's own detection (K=2 needs a second report)
        report_to_chain(ip, "test-fingerprint", who=2)
    print("reported", ip, flush=True)
