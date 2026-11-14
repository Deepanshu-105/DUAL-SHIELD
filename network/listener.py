"""Peer listener: polls the Fabric gateway for chaincode events (ThreatConsensusReached, ThreatOverruled) and blocks the IP.
Polling by event id (not a push subscription) so a dropped connection can never silently lose events: every event after the
last id seen is asked for again."""
import ipaddress, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "multi"))
import shield_os            # v10: Linux ipset/iptables or Windows Firewall
import ipcrypt
from chainlib import Chain

POLL = float(os.environ.get("POLL", "0.5"))
LOG = os.environ.get("PEER_LOG") or shield_os.log_path("peer_block.log")


def block(ip):
    ipaddress.ip_address(ip)
    shield_os.block_add(ip)
    line = "PEER_BLOCK ip=%s ts=%.3f" % (ip, time.time())
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def sensor_event(kind, sid):
    """v4: the chain can also confirm a misbehaving SENSOR (id like 'sensor:traffic-12'). No firewall rule
    applies: peers record it so gateways/dashboards stop trusting that sensor."""
    line = "SENSOR_%s id=%s ts=%.3f" % (kind, sid, time.time())
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def unblock(ip):
    if ip.startswith("sensor:"):
        return sensor_event("RELEASE", ip[7:])
    ipaddress.ip_address(ip)
    shield_os.block_del(ip)
    line = "PEER_UNBLOCK ip=%s ts=%.3f reason=overruled" % (ip, time.time())
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def run():
    chain = Chain()
    last = None
    while True:
        try:
            if last is None:                       # first start: only events from now on
                last = chain.head()
                print("subscribed: polling from event %d" % last, flush=True)
            evs, head = chain.events(last)
            if head < last:                        # the gateway's history was reset
                last = head
                continue
            for ev in evs:
                last = max(last, ev["id"])
                name = ev.get("name")
                if name not in ("ThreatConsensusReached", "ThreatOverruled"):
                    continue
                ip = ipcrypt.decode(ev.get("ip", ""))
                if ip is None:
                    print("UNREADABLE_EVENT (encrypted threat, wrong or missing CHAIN_IP_KEY)", flush=True)
                    continue
                if name == "ThreatOverruled":
                    print("OVERRULED ip=%s slashed=%d" % (ip, ev.get("slashedNodes", 0)), flush=True)
                    unblock(ip)
                    continue
                print("EVENT ip=%s count=%d" % (ip, ev.get("count", 0)), flush=True)
                if ip.startswith("sensor:"):
                    sensor_event("QUARANTINE", ip[7:])
                    continue
                block(ip)
            time.sleep(POLL)
        except Exception as e:
            print("listener error:", e, "- retrying in 2 s", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    run()
