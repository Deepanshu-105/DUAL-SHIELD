import asyncio, ipaddress, json, os, subprocess, time
import websockets
from eth_abi import decode
from web3 import Web3

DEP = json.load(open(os.environ.get("DEPLOY", "/opt/shield/localhost.json")))
WS = os.environ.get("CHAIN_WS", "ws://host.docker.internal:8545")
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

async def run():
    while True:
        try:
            async with websockets.connect(WS) as ws:
                await ws.send(json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
                    "params": ["logs", {"address": DEP["address"], "topics": [TOPIC]}]}))
                print("subscribed:", await ws.recv(), flush=True)
                async for msg in ws:
                    log = json.loads(msg).get("params", {}).get("result")
                    if not log:
                        continue
                    ip, ja3, count = decode(["string", "bytes32", "uint256"],
                                            bytes.fromhex(log["data"][2:]))
                    print("EVENT ip=%s count=%d" % (ip, count), flush=True)
                    block(ip)
        except Exception as e:
            print("listener error:", e, "- retrying in 2 s", flush=True)
            await asyncio.sleep(2)

asyncio.run(run())
