"""Client for the CityShield chaincode on Hyperledger Fabric, through the gateway on D (fabric/gateway/server.js).

  from chainlib import Chain
  c = Chain()                                   # GATEWAY_URL or D_IP:GATEWAY_PORT; mutual TLS when TLS=1
  c.report_threat("1.2.3.4", "fingerprint", who=1)
  c.tally("1.2.3.4")  ->  {"count": 1, "k": 2, "confirmed": False}
  evs, head = c.events(after)                   # chaincode events, e.g. ThreatConsensusReached

`who` is the Fabric identity used for the call: 0 owner/governor (Org1 Admin), 1 target node (Org1 User1), 2 peer node (Org2 User1),
3 Org1 User2, 4 Org2 User2, 5 Org2 Admin. The gateway decides which laptop may use which identity (certificate role).
No gas, no cryptocurrency: the endorsement policy of the channel (both organisations must sign) takes the place of gas-priced consensus.
Standard library only (plus multi/tlsutil.py for mutual TLS).
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "multi"))
import tlsutil

IDENTITY_NAMES = {0: "Org1MSP:Admin@org1.example.com", 1: "Org1MSP:User1@org1.example.com", 2: "Org2MSP:User1@org2.example.com",
                  3: "Org1MSP:User2@org1.example.com", 4: "Org2MSP:User2@org2.example.com", 5: "Org2MSP:Admin@org2.example.com"}


class ChainError(Exception):
    pass


def identity(x):
    """account index or full identity string -> identity string"""
    if x is None or x == "":
        return ""
    return IDENTITY_NAMES[int(x)] if str(x).isdigit() else str(x)


class Chain:
    def __init__(self, url=None, timeout=20):
        d = os.environ.get("D_IP", "127.0.0.1")
        port = os.environ.get("GATEWAY_PORT", "8600")
        self.url = url or os.environ.get("GATEWAY_URL") or "%s://%s:%s" % ("https" if tlsutil.enabled() else "http", d, port)
        self.timeout = timeout

    def _call(self, method, path, obj=None):
        body = json.dumps(obj).encode() if obj is not None else None
        code, raw, _ = tlsutil.request(self.url, method, path, {"content-type": "application/json"} if body else {}, body,
                                       expect_cn="dualshield-dashboard", timeout=self.timeout)
        try:
            out = json.loads(raw or b"{}")
        except ValueError:
            raise ChainError("gateway answered %d with something that is not JSON" % code)
        if code != 200 or out.get("ok") is False:
            raise ChainError(out.get("error", "gateway error %d" % code))
        return out

    def submit(self, who, fn, *args):
        """write: endorsed by both organisations, ordered, committed. Returns the chaincode's answer (string)."""
        return self._call("POST", "/tx", {"who": int(who), "fn": fn, "args": [str(a) for a in args]})["result"]

    def query(self, who, fn, *args):
        r = self._call("POST", "/query", {"who": int(who), "fn": fn, "args": [str(a) for a in args]})["result"]
        try:
            return json.loads(r)
        except ValueError:
            return r

    def events(self, after=0, limit=500):
        o = self._call("GET", "/events?after=%d&limit=%d" % (after, limit))
        return o["events"], o["head"]

    def head(self):
        return self._call("GET", "/health")["head"]

    # ---- convenience wrappers
    @staticmethod
    def fp(text):
        return hashlib.sha256(str(text).encode()).hexdigest()

    def report_threat(self, ip, fingerprint="manual", who=1):
        return self.submit(who, "reportThreat", ip, self.fp(fingerprint))

    def tally(self, ip, who=0):
        return self.query(who, "getTally", ip)

    def params(self):
        return self.query(0, "params")

    def register_node(self, who):
        return self.submit(who, "registerNode")

    def anchor_clean_state(self, ip, root_hex, t_attack, who=0):
        return self.submit(who, "anchorCleanState", ip, root_hex, int(t_attack))

    def clean_state(self, ip):
        return self.query(0, "getCleanState", ip)
