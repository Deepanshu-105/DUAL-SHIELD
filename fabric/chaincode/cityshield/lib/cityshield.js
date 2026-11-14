"use strict";
/*
 * CityShield chaincode (Hyperledger Fabric). A port of blockchain/contracts/CityShield.sol with the same rules:
 *   - only nodes approved by the owner may register; registering locks a stake (no gas, no money: a counter);
 *   - K independent reports within WINDOW seconds confirm a threat (quorumPct can raise K with the network size);
 *   - a report nobody confirms is a false report: slashExpired() takes the reporters' stake;
 *   - protected IPs can never be reported; a per-node hourly report cap; governance can overrule a confirmed threat;
 *   - multi-signature governance (propose / approve, M of N governors) for every sensitive change;
 *   - clean-state (Merkle root) anchors for recovery proof.
 * Identity: a caller is "<MSPID>:<certificate CN>", e.g. "Org1MSP:User1@org1.example.com". Fabric's own
 * endorsement policy decides which peers must agree on every transaction (see fabric/deploy). Fabric allows ONE
 * chaincode event per transaction, so all events of a call are returned as one "ShieldEvents" event holding a JSON list.
 */
const { Contract } = require("fabric-contract-api");
const crypto = require("crypto");

const K = 2, STAKE = 1, WINDOW = 60;
const P = { OVERRULE: 1, PROTECT: 2, UNPROTECT: 3, ADD_NODE: 4, REVOKE_NODE: 5, ADD_GOVERNOR: 6, REMOVE_GOVERNOR: 7, SET_THRESHOLD: 8, SET_QUORUM: 9, SET_RATE_LIMIT: 10 };

const ipKey = (ip) => crypto.createHash("sha256").update(String(ip)).digest("hex");
const num = (v, what) => {
  if (!/^\d+$/.test(String(v))) throw new Error("bad number for " + what);
  return Number(v);
};

class CityShield extends Contract {
  constructor() { super("CityShield"); }

  // ---- plumbing
  caller(ctx) {
    // getID() = "x509::<subject DN>::<issuer DN>"; the subject's CN names the caller (cryptogen: Admin@org1.example.com)
    const dn = String(ctx.clientIdentity.getID()).split("::")[1] || "";
    const m = /CN=([^,\/]+)/.exec(dn);
    return ctx.clientIdentity.getMSPID() + ":" + (m ? m[1] : dn);
  }
  now(ctx) {
    const ts = ctx.stub.getTxTimestamp();
    const s = ts.seconds;
    return typeof s === "number" ? s : typeof s.toNumber === "function" ? s.toNumber() : Number(s.low !== undefined ? s.low : s);
  }
  async get(ctx, key, dflt) {
    const b = await ctx.stub.getState(key);
    return b && b.length ? JSON.parse(b.toString()) : dflt;
  }
  async put(ctx, key, val) { await ctx.stub.putState(key, Buffer.from(JSON.stringify(val))); }
  async cfg(ctx) {
    const c = await this.get(ctx, "cfg", null);
    if (!c) throw new Error("not initialised: run initLedger first");
    return c;
  }
  emit(ctx, list) {
    if (list.length) ctx.stub.setEvent("ShieldEvents", Buffer.from(JSON.stringify(list)));
  }
  required(c) {
    if (!c.quorumPct) return K;
    const r = Math.floor((c.nodeCount * c.quorumPct + 99) / 100);
    return r < K ? K : r;
  }

  // ---- setup (the first caller becomes owner, approved node and first governor, threshold 1)
  async initLedger(ctx) {
    if (await this.get(ctx, "cfg", null)) throw new Error("already initialised");
    const me = this.caller(ctx);
    await this.put(ctx, "cfg", { owner: me, govCount: 1, govThreshold: 1, nodeCount: 0, slashedPool: 0, quorumPct: 0, maxReportsPerHour: 0, proposals: 0 });
    await this.put(ctx, "approved:" + me, true);
    await this.put(ctx, "gov:" + me, true);
    return JSON.stringify({ owner: me });
  }

  // ---- node management
  async addNode(ctx, node) {
    const c = await this.cfg(ctx);
    if (this.caller(ctx) !== c.owner || c.govThreshold !== 1) throw new Error("owner only");
    return this._addNode(ctx, node);
  }
  async revokeNode(ctx, node) {
    const c = await this.cfg(ctx);
    if (this.caller(ctx) !== c.owner || c.govThreshold !== 1) throw new Error("owner only");
    return this._revokeNode(ctx, c, node, []);
  }
  async _addNode(ctx, node) {
    await this.put(ctx, "approved:" + node, true);
    this.emit(ctx, [{ name: "NodeApproved", node }]);
  }
  async _revokeNode(ctx, c, node, ev) {
    await this.put(ctx, "approved:" + node, false);
    const amt = await this.get(ctx, "stake:" + node, 0);
    if (amt > 0) {
      await this.put(ctx, "stake:" + node, 0);
      c.slashedPool += amt;
      c.nodeCount--;
    }
    await this.put(ctx, "cfg", c);
    ev.push({ name: "NodeRevoked", node, forfeited: amt });
    this.emit(ctx, ev);
  }
  async registerNode(ctx) {
    const me = this.caller(ctx), c = await this.cfg(ctx);
    if (!(await this.get(ctx, "approved:" + me, false))) throw new Error("not approved by owner");
    if ((await this.get(ctx, "stake:" + me, 0)) > 0) throw new Error("already registered");
    await this.put(ctx, "stake:" + me, STAKE);
    c.nodeCount++;
    await this.put(ctx, "cfg", c);
    return JSON.stringify({ node: me, stake: STAKE });
  }

  // ---- threat reports
  async reportThreat(ctx, ip, ja3) {
    const me = this.caller(ctx), c = await this.cfg(ctx), id = ipKey(ip), now = this.now(ctx);
    if ((await this.get(ctx, "stake:" + me, 0)) <= 0) throw new Error("not staked");
    if (await this.get(ctx, "prot:" + id, false)) throw new Error("protected IP");
    if (c.maxReportsPerHour > 0) {
      const rk = "rate:" + me + ":" + Math.floor(now / 3600);
      const n = (await this.get(ctx, rk, 0)) + 1;
      if (n > c.maxReportsPerHour) throw new Error("rate limit");
      await this.put(ctx, rk, n);
    }
    const t = (await this.get(ctx, "threat:" + id, null)) || { count: 0, firstAt: 0, confirmed: false, settled: false, ja3: "", reporters: [], confirmedAt: 0, overruled: false, ip };
    if (t.settled) throw new Error("threat settled");
    if (await this.get(ctx, "voted:" + id + ":" + me, false)) throw new Error("already reported");
    if (t.count === 0) { t.firstAt = now; t.ja3 = String(ja3 || ""); }
    else if (!t.confirmed && now > t.firstAt + WINDOW) throw new Error("window expired");
    await this.put(ctx, "voted:" + id + ":" + me, true);
    t.reporters.push(me);
    t.count++;
    const ev = [{ name: "ThreatReported", node: me, ip, count: t.count }];
    if (!t.confirmed && t.count >= this.required(c)) {
      t.confirmed = true;
      t.confirmedAt = now;
      ev.push({ name: "ThreatConsensusReached", ip, ja3: t.ja3, count: t.count });
    }
    await this.put(ctx, "threat:" + id, t);
    this.emit(ctx, ev);
    return JSON.stringify({ count: t.count, confirmed: t.confirmed });
  }
  async getTally(ctx, ip) {
    const c = await this.cfg(ctx);
    const t = await this.get(ctx, "threat:" + ipKey(ip), null);
    return JSON.stringify({ count: t ? t.count : 0, k: this.required(c), confirmed: t ? t.confirmed : false });
  }
  async requiredReports(ctx) { return JSON.stringify(this.required(await this.cfg(ctx))); }
  async isProtected(ctx, ip) { return JSON.stringify(await this.get(ctx, "prot:" + ipKey(ip), false)); }
  async blockInfo(ctx, ip) {
    const t = await this.get(ctx, "threat:" + ipKey(ip), null);
    return JSON.stringify({ active: !!(t && t.confirmed && !t.overruled), confirmedAt: t ? t.confirmedAt : 0 });
  }
  async slashExpired(ctx, ip) {
    const c = await this.cfg(ctx), id = ipKey(ip), now = this.now(ctx);
    const t = await this.get(ctx, "threat:" + id, null);
    if (!t || t.count === 0) throw new Error("no such threat");
    if (t.confirmed) throw new Error("already confirmed");
    if (t.settled) throw new Error("already settled");
    if (!(now > t.firstAt + WINDOW)) throw new Error("window still open");
    t.settled = true;
    const ev = [];
    for (const r of t.reporters) {
      const amt = await this.get(ctx, "stake:" + r, 0);
      if (amt > 0) {
        await this.put(ctx, "stake:" + r, 0);
        c.slashedPool += amt;
        ev.push({ name: "NodeSlashed", node: r, ip, amount: amt });
      }
    }
    await this.put(ctx, "threat:" + id, t);
    await this.put(ctx, "cfg", c);
    this.emit(ctx, ev);
  }

  // ---- clean-state anchor
  async anchorCleanState(ctx, ip, merkleRoot, tAttack) {
    const me = this.caller(ctx);
    if ((await this.get(ctx, "stake:" + me, 0)) <= 0) throw new Error("not staked");
    if (!/^[0-9a-fA-F]{64}$/.test(merkleRoot)) throw new Error("merkleRoot must be 64 hex characters");
    await this.put(ctx, "clean:" + ipKey(ip), { merkleRoot: merkleRoot.toLowerCase(), tAttack: num(tAttack, "tAttack"), anchored: true });
    this.emit(ctx, [{ name: "CleanStateAnchored", ip, merkleRoot: merkleRoot.toLowerCase(), tAttack: Number(tAttack) }]);
  }
  async getCleanState(ctx, ip) {
    return JSON.stringify(await this.get(ctx, "clean:" + ipKey(ip), { merkleRoot: "0".repeat(64), tAttack: 0, anchored: false }));
  }

  // ---- multi-signature governance
  // NOTE: inside one Fabric transaction getState() does NOT see the transaction's own earlier putState(), so the
  // objects are passed along (and written once at the end) instead of being re-read.
  async propose(ctx, kind, ip, node, value) {
    const me = this.caller(ctx), c = await this.cfg(ctx);
    if (!(await this.get(ctx, "gov:" + me, false))) throw new Error("governor only");
    const k = num(kind, "kind");
    if (k < 1 || k > 10) throw new Error("bad kind");
    const id = c.proposals++;
    const p = { kind: k, ip: ip || "", node: node || "", value: num(value || "0", "value"), approvals: 0, executed: false, signed: [] };
    const ev = [{ name: "ProposalCreated", id, kind: k, by: me }];
    await this._sign(ctx, c, id, p, me, ev);
    return JSON.stringify({ id });
  }
  async approve(ctx, id) {
    const me = this.caller(ctx), c = await this.cfg(ctx);
    if (!(await this.get(ctx, "gov:" + me, false))) throw new Error("governor only");
    const n = num(id, "id");
    const p = await this.get(ctx, "proposal:" + n, null);
    if (!p) throw new Error("no such proposal");
    await this._sign(ctx, c, n, p, me, []);
  }
  async _sign(ctx, c, id, p, me, ev) {
    if (p.executed) throw new Error("already executed");
    if (p.signed.includes(me)) throw new Error("already signed");
    p.signed.push(me);
    p.approvals++;
    ev.push({ name: "ProposalApproved", id, by: me, approvals: p.approvals });
    if (p.approvals >= c.govThreshold) {
      p.executed = true;
      await this._execute(ctx, c, p, ev);
      ev.push({ name: "ProposalExecuted", id, kind: p.kind });
    }
    await this.put(ctx, "proposal:" + id, p);
    await this.put(ctx, "cfg", c);
    this.emit(ctx, ev);
  }
  async _execute(ctx, c, p, ev) {
    const k = p.kind;
    if (k === P.OVERRULE) {
      const id = ipKey(p.ip);
      const t = await this.get(ctx, "threat:" + id, null);
      if (!t || !t.confirmed || t.overruled) throw new Error("nothing to overrule");
      t.overruled = true; t.settled = true;
      let n = 0;
      for (const r of t.reporters) {
        const amt = await this.get(ctx, "stake:" + r, 0);
        if (amt > 0) {
          await this.put(ctx, "stake:" + r, 0);
          c.slashedPool += amt; c.nodeCount--; n++;
          ev.push({ name: "NodeSlashed", node: r, ip: p.ip, amount: amt });
        }
      }
      await this.put(ctx, "threat:" + id, t);
      ev.push({ name: "ThreatOverruled", ip: p.ip, slashedNodes: n });
    } else if (k === P.PROTECT || k === P.UNPROTECT) {
      await this.put(ctx, "prot:" + ipKey(p.ip), k === P.PROTECT);
      ev.push({ name: "IpProtected", ip: p.ip, on: k === P.PROTECT });
    } else if (k === P.ADD_NODE) {
      await this.put(ctx, "approved:" + p.node, true);
      ev.push({ name: "NodeApproved", node: p.node });
    } else if (k === P.REVOKE_NODE) {
      await this.put(ctx, "approved:" + p.node, false);
      const amt = await this.get(ctx, "stake:" + p.node, 0);
      if (amt > 0) { await this.put(ctx, "stake:" + p.node, 0); c.slashedPool += amt; c.nodeCount--; }
      ev.push({ name: "NodeRevoked", node: p.node, forfeited: amt });
    } else if (k === P.ADD_GOVERNOR) {
      if (await this.get(ctx, "gov:" + p.node, false)) throw new Error("already governor");
      await this.put(ctx, "gov:" + p.node, true); c.govCount++;
    } else if (k === P.REMOVE_GOVERNOR) {
      if (!(await this.get(ctx, "gov:" + p.node, false)) || c.govCount - 1 < c.govThreshold) throw new Error("cannot remove");
      await this.put(ctx, "gov:" + p.node, false); c.govCount--;
    } else if (k === P.SET_THRESHOLD) {
      if (p.value < 1 || p.value > c.govCount) throw new Error("bad threshold");
      c.govThreshold = p.value; ev.push({ name: "ParamChanged", param: "govThreshold", value: p.value });
    } else if (k === P.SET_QUORUM) {
      if (p.value > 100) throw new Error("percent");
      c.quorumPct = p.value; ev.push({ name: "ParamChanged", param: "quorumPct", value: p.value });
    } else if (k === P.SET_RATE_LIMIT) {
      c.maxReportsPerHour = p.value; ev.push({ name: "ParamChanged", param: "maxReportsPerHour", value: p.value });
    }
  }

  // ---- read-only helpers for clients and the dashboard
  async proposalCount(ctx) { return JSON.stringify((await this.cfg(ctx)).proposals); }
  async getProposal(ctx, id) {
    const p = await this.get(ctx, "proposal:" + num(id, "id"), null);
    if (!p) throw new Error("no such proposal");
    return JSON.stringify({ kind: p.kind, ip: p.ip, node: p.node, value: p.value, approvals: p.approvals, executed: p.executed });
  }
  async params(ctx) {
    const c = await this.cfg(ctx);
    return JSON.stringify({ K, STAKE, WINDOW, owner: c.owner, govCount: c.govCount, govThreshold: c.govThreshold, nodeCount: c.nodeCount,
      slashedPool: c.slashedPool, quorumPct: c.quorumPct, maxReportsPerHour: c.maxReportsPerHour, required: this.required(c) });
  }
  async nodeInfo(ctx, node) {
    return JSON.stringify({ approved: await this.get(ctx, "approved:" + node, false), stake: await this.get(ctx, "stake:" + node, 0), governor: await this.get(ctx, "gov:" + node, false) });
  }
  async whoami(ctx) { return this.caller(ctx); }
}

module.exports = CityShield;
