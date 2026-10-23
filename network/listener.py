"""Peer listener: polls the chain over HTTP for ThreatConsensusReached and blocks the IP.
Polling by block number (not a websocket subscription) so a dropped connection can never
silently lose events: every block after the last one seen is queried."""
import ipaddress, json, os, subprocess, time
from eth_abi import decode
from web3 import Web3

DEP = json.load(open(os.environ.get("DEPLOY", "/opt/shield/localhost.json")))
HTTP = os.environ.get("CHAIN_HTTP", "http://host.docker.internal:8545")
POLL = float(os.environ.get("POLL", "0.2"))
LOG = "/var/log/peer_block.log"

h = Web3.keccak(text="ThreatConsensusReached(string,bytes32,uint256)").hex()
TOPIC = h if h.startswith("0x") else "0x" + h


def block(ip):
    ipaddress.ip_address(ip)
    subprocess.run(["ipset", "add", "city_blacklist", ip, "-exist"], check=True)
    line = "PEER_BLOCK ip=%s ts=%.3f" % (ip, time.time())
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def run():
    w3 = Web3(Web3.HTTPProvider(HTTP))
    addr = Web3.to_checksum_address(DEP["address"])
    last = None
    while True:
        try:
            head = w3.eth.block_number
            if last is None or head < last:        # first start, or the chain was reset
                last = head
                print("subscribed: polling from block %d" % head, flush=True)
            elif head > last:
                logs = w3.eth.get_logs({"address": addr, "topics": [TOPIC],
                                        "fromBlock": last + 1, "toBlock": head})
                for lg in logs:
                    ip, ja3, count = decode(["string", "bytes32", "uint256"], bytes(lg["data"]))
                    print("EVENT ip=%s count=%d" % (ip, count), flush=True)
                    block(ip)
                last = head
            time.sleep(POLL)
        except Exception as e:
            print("listener error:", e, "- retrying in 2 s", flush=True)
            time.sleep(2)


run()
