"""One-off manual report to the Fabric ledger (needs the gateway: D_IP / GATEWAY_URL). Usage: python3 report_threat.py [IP] [fingerprint]"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "network"))
from chainlib import Chain

c = Chain()
ip = sys.argv[1] if len(sys.argv) > 1 else "172.30.0.12"
c.report_threat(ip, sys.argv[2] if len(sys.argv) > 2 else "hassh-abc123", who=1)
print("tally:", c.tally(ip))
