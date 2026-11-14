"""A set of IPs AND networks (CIDR) for "never block" lists. `ip in NetSet(["10.0.0.5", "192.168.0.0/16"])`.
Why: many real users share one address (campus or mobile NAT). Blocking that address would block all of them,
so such ranges go into WHITELIST_CIDRS and are never counted or blocked by any detector."""
import ipaddress, os


class NetSet:
    def __init__(self, items=()):
        self.ips, self.nets = set(), []
        for x in items:
            self.add(x)

    def add(self, x):
        x = str(x).strip()
        if not x:
            return
        if "/" in x:
            self.nets.append(ipaddress.ip_network(x, strict=False))
        else:
            self.ips.add(x)

    def __contains__(self, ip):
        if ip in self.ips:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)

    def __or__(self, other):
        r = NetSet()
        r.ips, r.nets = set(self.ips), list(self.nets)
        for x in (other.ips if isinstance(other, NetSet) else other):
            r.add(x)
        if isinstance(other, NetSet):
            r.nets += other.nets
        return r

    def __iter__(self):
        return iter(sorted(self.ips) + [str(n) for n in self.nets])

    def __bool__(self):
        return bool(self.ips or self.nets)


def from_env():
    return NetSet(x for x in os.environ.get("WHITELIST_CIDRS", "").split(","))
