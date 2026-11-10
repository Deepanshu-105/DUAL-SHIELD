import ipaddress, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipcrypt
from chainlib import Chain

_chain = None


def chain():
    global _chain
    _chain = _chain or Chain()
    return _chain


def report_to_chain(ip, fingerprint="manual", who=1):
    """Call this from detector/ssh_parser.py right after its ipset add. who: 1 = target node, 2 = peer node."""
    chain().report_threat(ipcrypt.encode(ip), fingerprint, who=who)


if __name__ == "__main__":
    ip = sys.argv[1]
    ipaddress.ip_address(ip)
    if "--block" in sys.argv:
        subprocess.run(["ipset", "add", "city_blacklist", ip, "-exist"], check=True)
        print("TARGET_BLOCK ip=%s ts=%.3f" % (ip, time.time()), flush=True)
    who = int(sys.argv[sys.argv.index("--who") + 1]) if "--who" in sys.argv else int(os.environ.get("NODE_ID", "1"))
    report_to_chain(ip, "test-fingerprint", who=who)
    if os.environ.get("COREPORT") == "1":
        # DEMO ONLY: stands in for the peer's own detection (K=2 needs a second report)
        report_to_chain(ip, "test-fingerprint", who=2 if who == 1 else 1)
    print("reported", ip, flush=True)
