#!/usr/bin/env python3
"""Peer trust monitor (v13.13) - protects the network from a node that turns bad (compromised laptop, insider).  Runs on D next to the dashboard.
Reads every chain event and keeps a score per node:
   +100  reported an address of our own infrastructure (D, T, P, gateway ...)           = trying to get the network to block itself  -> SUSPEND at once
   +50   a confirmed threat it reported was overruled by the governors                    (they judged it a false block)
   +20   its lone report expired unconfirmed and it was slashed                          (a first mistake is possible; repeated ones are not)
   +30   more than RATE_MAX reports within 10 minutes                                     (flooding)
   score halves every 24 h.   40 = WATCH (alert)   100 = SUSPEND
 SUSPEND: audit line + optional webhook (TRUST_WEBHOOK) and, with --act propose (default), the owner proposes "Revoke a node". With governor threshold 1 that revokes it
 at once (stake forfeited, it can no longer report); with a higher threshold the governors approve it in the dashboard. --act alert never changes the chain.
 Also an ALERT (no points): two nodes that alone make every confirmed threat while a third node exists (possible collusion; with several organisations use minOrgs=2).
 Never acts against the owner, a governor or a node listed in TRUST_EXEMPT.   State file for the dashboard: $TRUST_FILE (default multi/logs/peer_trust.json).
   python3 network/peer_trust.py [--act alert|propose] [--once] [--from EVENT_ID]   (old history is not replayed: events have no time stamp)
"""
import json, os, sys, time, collections, ipaddress
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
POINTS = {"INFRA_FRAME": 100, "OVERRULED": 50, "SLASHED": 20, "FLOOD": 30, "NOT_ENFORCING": 40, "SILENT": 30, "BAD_ANSWER": 60}
ENFORCE_GRACE = float(os.environ.get("TRUST_ENFORCE_GRACE", "30"))     # seconds a node has to apply a confirmed block
DOWN_SECS = float(os.environ.get("TRUST_DOWN_SECS", "180"))           # silent this long = SILENT
EXPECT_TTL = float(os.environ.get("CONSENSUS_TTL", "3600")) or 86400  # a block without local evidence expires on the peer after this
AUDIT_EVERY = float(os.environ.get("TRUST_AUDIT_EVERY", "15"))
WATCH, SUSPEND = 40, 100
HALF_LIFE = 24 * 3600.0
RATE_MAX = int(os.environ.get("TRUST_RATE_MAX", "30")); RATE_WIN = 600.0
STATE_FILE = os.environ.get("TRUST_FILE") or os.path.join(HERE, "..", "multi", "logs", "peer_trust.json")
AUDIT_FILE = os.environ.get("TRUST_AUDIT") or os.path.join(HERE, "..", "multi", "logs", "peer_trust_audit.log")

def infra_set():
    out = set()
    for k in ("D_IP", "T_IP", "P_IP", "WHITELIST_EXTRA", "INFRA_IPS"):
        for x in os.environ.get(k, "").split(","):
            x = x.strip()
            if x:
                try: out.add(str(ipaddress.ip_address(x)))
                except ValueError: pass
    return out

class Trust:
    def __init__(self, infra=None, act="propose", exempt=(), actions=None, now=time.time):
        self.infra = set(infra or []); self.act = act; self.exempt = set(exempt); self.now = now
        self.nodes = {}                      # node -> {score, t, state, why:[...], reports:deque, acted}
        self.last_reporters = collections.Counter()
        self.alerts = []; self.pending = []
        self.expected = {}; self.flagged = set(); self.down = {}; self.live = {}; self.badsig = {}
        self.do = actions or {}              # callbacks: suspend(node) -> text
    def _n(self, node):
        return self.nodes.setdefault(node, {"score": 0.0, "t": self.now(), "state": "OK", "why": [], "reports": collections.deque(), "acted": -1e12})
    def _decay(self, n):
        t = self.now(); n["score"] *= 0.5 ** ((t - n["t"]) / HALF_LIFE); n["t"] = t
    def _add(self, node, why):
        if node in self.exempt: return
        n = self._n(node); self._decay(n); n["score"] += POINTS[why]; n["why"] = (n["why"] + ["%s@%d" % (why, self.now())])[-8:]
        old = n["state"]; n["state"] = "SUSPEND" if n["score"] >= SUSPEND else "WATCH" if n["score"] >= WATCH else "OK"
        if n["state"] != old and n["state"] != "OK": self.alert("%s -> %s (%s)" % (node, n["state"], ", ".join(n["why"][-3:])))
        if n["state"] == "SUSPEND" and self.now() - n["acted"] > 3600 and self.act == "propose" and "suspend" in self.do:
            n["acted"] = self.now(); self.alert("ACTION %s: %s" % (node, self.do["suspend"](node)))
    def alert(self, text):
        self.alerts.append(text); self.pending.append(text); line = "%s TRUST %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), text); print(line, flush=True)
        try:
            os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True); open(AUDIT_FILE, "a").write(line + "\n")
        except OSError: pass
    def event(self, e, decode=lambda x: x, tally=None, nodes_staked=0):
        name = e.get("name")
        if name == "ThreatReported":
            node = e.get("node"); ip = decode(e.get("ip", ""))
            if node in self.exempt: return
            n = self._n(node); t = self.now(); n["reports"].append(t)
            while n["reports"] and t - n["reports"][0] > RATE_WIN: n["reports"].popleft()
            if ip in self.infra: self._add(node, "INFRA_FRAME")
            if len(n["reports"]) == RATE_MAX + 1: self._add(node, "FLOOD")
        elif name == "NodeSlashed" and e.get("ip") is not None and not str(e.get("ip", "")).startswith("sensor:"):
            if e.get("amount"): self._add(e.get("node"), "SLASHED")
        elif name == "ThreatOverruled":
            self.forget(decode(e.get("ip", "")))
            for r in (tally or {}).get("reporters", []): self._add(r, "OVERRULED")
        elif name == "ThreatConsensusReached" and e.get("ip"):
            self.expect(decode(e.get("ip", "")))
            if tally and nodes_staked >= 3: self._collusion(tally, nodes_staked)
    def _collusion(self, tally, nodes_staked):
        if True:
            rep = tuple(sorted(tally.get("reporters", [])))
            if len(rep) == 2:
                self.last_reporters[rep] += 1
                if self.last_reporters[rep] == 5: self.alert("possible collusion: %s and %s alone confirmed 5 threats while %d nodes are staked (set minOrgs=2 and check them)" % (rep[0], rep[1], nodes_staked))
    # ---- v13.14: audit of what a node REALLY does (its firewall and its agent), asked through the signed agent API of that laptop ----
    def expect(self, ip):
        import block_policy
        if not ip or ip.startswith("sensor:"): return
        try:
            if block_policy.never_block_reason(ip, self.infra): return
        except ValueError:
            return                      # not an IP address: nothing a firewall could block
        self.expected[ip] = self.now()
    def forget(self, ip):
        self.expected.pop(ip, None)
    def audit(self, node, status, required=2, nodes_total=0):
        """status: {"state": "ok"|"down"|"bad", "ips": [blocked addresses] or None (the node cannot tell)}"""
        t = self.now(); st = status.get("state")
        if st == "down":
            first = self.down.setdefault(node, t); self.live[node] = False
            if t - first >= DOWN_SECS and not self.nodes.get(node, {}).get("silent_flag"):
                self._n(node)["silent_flag"] = True; self._add(node, "SILENT"); self.alert("%s is silent for %d s (agent unreachable)" % (node, t - first))
        elif st == "bad":
            self.live[node] = False
            if t - self.badsig.get(node, -1e12) > 600: self.badsig[node] = t; self._add(node, "BAD_ANSWER"); self.alert("%s sent an answer with a wrong signature (forged or tampered)" % node)
        elif st == "ok":
            self.live[node] = True; self.down.pop(node, None)
            if node in self.nodes: self.nodes[node].pop("silent_flag", None)
            ips = status.get("ips")
            if ips is not None:
                have = set(ips)
                for ip, t0 in list(self.expected.items()):
                    if t - t0 > EXPECT_TTL: self.expected.pop(ip, None); continue
                    if t - t0 >= ENFORCE_GRACE and ip not in have and (node, ip) not in self.flagged:
                        self.flagged.add((node, ip)); self._add(node, "NOT_ENFORCING"); self.alert("%s did not apply the confirmed block of %s (%d s)" % (node, ip, t - t0))
        up = sum(1 for v in self.live.values() if v)
        if self.live and up < required and not getattr(self, "_q_alerted", False):
            self._q_alerted = True; self.alert("only %d node(s) answer: the quorum of %d can NOT be reached right now" % (up, required))
        elif up >= required: self._q_alerted = False
    def snapshot(self):
        out = {}
        for k, n in self.nodes.items():
            self._decay(n); out[k] = {"score": round(n["score"], 1), "state": n["state"], "why": n["why"][-4:]}
        return {"updated": int(self.now()), "act": self.act, "nodes": out, "alerts": self.alerts[-10:]}

def main():
    from chainlib import Chain
    import ipcrypt
    a = sys.argv[1:]; act = a[a.index("--act") + 1] if "--act" in a else "propose"
    c = Chain(); owner = c.params().get("owner")
    gov_cache = {}
    def exempt_check(node):
        if node == owner: return True
        if node not in gov_cache: gov_cache[node] = bool(c.query(0, "nodeInfo", node).get("governor"))
        return gov_cache[node]
    def suspend(node):
        if exempt_check(node): return "refused: owner/governor"
        r = c.submit(0, "propose", 5, "", node, 0)
        return "revoke proposal %s (executes at once when the governor threshold is 1)" % r
    T = Trust(infra=infra_set(), act=act, exempt=[x for x in os.environ.get("TRUST_EXEMPT", "").split(",") if x] + [owner], actions={"suspend": suspend})
    from chainlib import IDENTITY_NAMES
    import subprocess
    roles = [(r, w) for r, w in (("T", 1), ("P", 2)) if r in os.environ.get("TRUST_AUDIT_ROLES", "T,P").split(",") and len(os.environ.get("AGENT_SECRET_" + r, "")) >= 16]
    last_audit = 0
    def poll_agent(role):
        ac = os.path.join(HERE, "..", "multi", "agent_call.py")
        try: r = subprocess.run([sys.executable, ac, role, "GET", "/ipset"], capture_output=True, text=True, timeout=20, env=dict(os.environ))
        except subprocess.TimeoutExpired: return {"state": "down"}
        if r.returncode == 1: return {"state": "down"}
        if r.returncode == 2: return {"state": "bad"}
        try: ips = json.loads(r.stdout).get("ips")
        except ValueError: ips = None
        return {"state": "ok", "ips": ips}
    print("PEER_AUDIT nodes=%s" % (",".join(r for r, _ in roles) or "none (AGENT_SECRET_T / AGENT_SECRET_P not in the environment)"), flush=True)
    hook = os.environ.get("TRUST_WEBHOOK")
    # Events carry no time stamp, so old history is NOT replayed (it would count as fresh): start after the newest event, or resume where the saved state stopped.
    saved = {}
    try: saved = json.load(open(STATE_FILE))
    except Exception: pass
    if "--from" in a: last = int(a[a.index("--from") + 1])
    elif "last" in saved: last = int(saved["last"])
    else: last = c.events(0, 1)[1]
    for k, v in (saved.get("nodes") or {}).items():
        n = T._n(k); n.update(score=float(v.get("score", 0)), state=v.get("state", "OK"), why=list(v.get("why", [])), t=float(saved.get("updated", T.now())))
    print("PEER_TRUST_ON act=%s infra=%s" % (act, ",".join(sorted(T.infra)) or "-"), flush=True)
    while True:
        try:
            evs, head = c.events(last)
            for e in evs:
                last = max(last, e["id"]); tally = None
                if e.get("name") in ("ThreatConsensusReached", "ThreatOverruled"):
                    try: tally = c.query(0, "getTally", e.get("ip", ""))
                    except Exception: tally = None
                T.event(e, decode=lambda x: ipcrypt.decode(x) if x else x, tally=tally, nodes_staked=c.params().get("nodeCount", 0))
            if time.time() - last_audit >= AUDIT_EVERY:
                last_audit = time.time()
                for role, who in roles:
                    T.audit(IDENTITY_NAMES[who], poll_agent(role), required=c.params().get("required", 2), nodes_total=c.params().get("nodeCount", 0))
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            tmp = STATE_FILE + ".tmp"; snap = T.snapshot(); snap["last"] = last; json.dump(snap, open(tmp, "w")); os.replace(tmp, STATE_FILE)
            if hook and T.pending:
                import urllib.request
                msg, T.pending = "; ".join(T.pending[:5]), []
                try: urllib.request.urlopen(urllib.request.Request(hook, json.dumps({"text": "Dual-Shield trust: " + msg}).encode(), {"content-type": "application/json"}), timeout=5)
                except Exception: pass
            T.pending = []
        except Exception as ex:
            print("trust loop:", ex, flush=True)
        if "--once" in a: break
        time.sleep(2)

if __name__ == "__main__":
    main()
