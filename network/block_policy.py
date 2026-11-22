"""Rules a PEER applies before it turns a chain consensus into a firewall block (v13.14). Even a consensus can be wrong or forged by two bad nodes, so:
  1 never block our own infrastructure: D, T, P, the gateway, this machine, loopback, link-local, multicast, the DNS servers and the default gateway, INFRA_IPS
  2 a block that this node never saw evidence for (no failed login of its own) expires by itself after CONSENSUS_TTL seconds (default 3600; 0 = never): a framing heals, a real attacker is blocked again
    by the next report. A block with local evidence stays until a governor overrules it.
  3 circuit breaker: more than CB_MAX new consensus blocks within CB_WINDOW seconds (default 20 / 600) = mass framing or a runaway: further blocks are held unless this node saw the address itself; an alert is printed
State is kept in a small JSON file so a restart does not forget the expiries."""
import ipaddress, json, os, re, socket, time

def local_infra():
    """addresses that must never be blocked here, from the environment and from this machine"""
    out = set()
    for k in ("D_IP", "T_IP", "P_IP", "WHITELIST_EXTRA", "INFRA_IPS"):
        for x in os.environ.get(k, "").split(","):
            x = x.strip()
            if x:
                try: out.add(str(ipaddress.ip_address(x)))
                except ValueError: pass
    try:
        for ln in open("/etc/resolv.conf"):
            m = re.match(r"^\s*nameserver\s+(\S+)", ln)
            if m: out.add(m.group(1))
    except OSError: pass
    try:
        for ln in open("/proc/net/route").read().splitlines()[1:]:      # default gateway (Linux)
            f = ln.split()
            if len(f) > 2 and f[1] == "00000000":
                out.add(socket.inet_ntoa(bytes.fromhex(f[2])[::-1]))
    except (OSError, ValueError): pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.add(info[4][0])
    except OSError: pass
    return out

def never_block_reason(ip, infra):
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local: return "special address"
    if str(a) in infra: return "our own infrastructure"
    return None

class Policy:
    def __init__(self, block, unblock, infra=None, ttl=None, cb_max=None, cb_win=None, state_file=None, now=time.time, log=print):
        self.block, self.unblock, self.now, self.log = block, unblock, now, log
        self.infra = set(infra) if infra is not None else local_infra()
        self.ttl = float(os.environ.get("CONSENSUS_TTL", "3600")) if ttl is None else ttl
        self.cb_max = int(os.environ.get("CB_MAX", "20")) if cb_max is None else cb_max
        self.cb_win = float(os.environ.get("CB_WINDOW", "600")) if cb_win is None else cb_win
        self.file = state_file; self.exp = {}; self.recent = []
        try: self.exp = json.load(open(self.file))["exp"] if self.file else {}
        except Exception: self.exp = {}
    def _save(self):
        if not self.file: return
        try:
            tmp = self.file + ".tmp"; json.dump({"exp": self.exp}, open(tmp, "w")); os.replace(tmp, self.file)
        except OSError: pass
    def consensus(self, ip, local_evidence):
        why = never_block_reason(ip, self.infra)
        if why:
            self.log("REFUSED ip=%s (%s): a consensus asked to block it" % (ip, why)); return "REFUSED"
        t = self.now(); self.recent = [x for x in self.recent if t - x < self.cb_win]
        if self.cb_max and len(self.recent) >= self.cb_max and not local_evidence:
            self.log("CIRCUIT_BREAKER ip=%s held: %d new blocks in %d s (mass framing?)" % (ip, len(self.recent), self.cb_win)); return "HELD"
        self.recent.append(t)
        self.block(ip)
        if local_evidence or not self.ttl: self.exp.pop(ip, None)
        else: self.exp[ip] = t + self.ttl
        self._save(); return "BLOCKED"
    def release(self, ip):
        self.exp.pop(ip, None); self._save()
    def tick(self):
        t = self.now(); gone = [ip for ip, e in self.exp.items() if e <= t]
        for ip in gone:
            try: self.unblock(ip, "ttl")
            except Exception as e: self.log("unblock %s failed: %s" % (ip, e)); continue
            self.exp.pop(ip, None)
        if gone: self._save()
        return gone
