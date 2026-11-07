"use strict";
// Unit tests for the chaincode with an in-memory ledger. Same rules as the Solidity tests (CityShield/Hardening).
const assert = require("assert");
const CityShield = require("../lib/cityshield");

class Ledger {
  constructor() { this.state = new Map(); this.t = 1_000_000; this.events = []; }
  ctxFor(msp, cn) {
    const L = this;
    L.pending = new Map();
    return {
      clientIdentity: { getMSPID: () => msp, getID: () => "x509::CN=" + cn + ",OU=client,L=San Francisco,ST=California,C=US::CN=ca.example.com,O=example.com,L=San Francisco,ST=California,C=US" },
      stub: {
        // Fabric semantics: getState sees only the committed state, never this transaction's own writes
        getState: async (k) => (L.state.has(k) ? Buffer.from(L.state.get(k)) : Buffer.alloc(0)),
        putState: async (k, v) => { L.pending.set(k, Buffer.from(v).toString()); },
        getTxTimestamp: () => ({ seconds: { toNumber: () => L.t }, nanos: 0 }),
        setEvent: (n, p) => { L.events.push(...JSON.parse(p.toString())); },
      },
    };
  }
}
// run one transaction: state changes only commit if it succeeds (as Fabric does)
async function tx(L, who, fn, ...args) {
  const ev = L.events.length;
  try {
    const out = await new CityShield()[fn](L.ctxFor(...who), ...args.map(String));
    for (const [k, v] of L.pending) L.state.set(k, v);       // commit
    return out;
  } catch (e) { L.events.length = ev; throw e; }
}
const rejects = async (p, msg) => { await assert.rejects(p, (e) => (msg ? e.message.includes(msg) : true)); };
const OWNER = ["Org1MSP", "Admin@org1"], A = ["Org1MSP", "User1@org1"], B = ["Org2MSP", "User1@org2"], C = ["Org1MSP", "User2@org1"], X = ["Org3MSP", "stranger"];
const id = (w) => w[0] + ":" + w[1];
const IP = "198.51.100.9", ROOT = "ab".repeat(32);

async function setup() {
  const L = new Ledger();
  await tx(L, OWNER, "initLedger");
  for (const w of [A, B, C]) { await tx(L, OWNER, "addNode", id(w)); await tx(L, w, "registerNode"); }
  return L;
}
const q = async (L, fn, ...a) => JSON.parse(await tx(L, OWNER, fn, ...a));

describe("setup and membership", () => {
  it("initLedger can run once, owner is first governor, threshold 1", async () => {
    const L = new Ledger();
    await tx(L, OWNER, "initLedger");
    await rejects(tx(L, OWNER, "initLedger"), "already initialised");
    const p = await q(L, "params");
    assert.strictEqual(p.owner, id(OWNER)); assert.strictEqual(p.govThreshold, 1); assert.strictEqual(p.required, 2);
  });
  it("only an approved node can register, once", async () => {
    const L = new Ledger(); await tx(L, OWNER, "initLedger");
    await rejects(tx(L, A, "registerNode"), "not approved");
    await tx(L, OWNER, "addNode", id(A)); await tx(L, A, "registerNode");
    await rejects(tx(L, A, "registerNode"), "already registered");
    assert.strictEqual((await q(L, "params")).nodeCount, 1);
  });
  it("a stranger cannot add nodes", async () => {
    const L = await setup();
    await rejects(tx(L, X, "addNode", id(X)), "owner only");
  });
  it("revoking a node forfeits its stake", async () => {
    const L = await setup();
    await tx(L, OWNER, "revokeNode", id(A));
    const n = await q(L, "nodeInfo", id(A));
    assert.strictEqual(n.approved, false); assert.strictEqual(n.stake, 0);
    const p = await q(L, "params"); assert.strictEqual(p.slashedPool, 1); assert.strictEqual(p.nodeCount, 2);
  });
});

describe("threat consensus", () => {
  it("one report is not enough, the second confirms (K=2)", async () => {
    const L = await setup();
    await tx(L, A, "reportThreat", IP, "ja3x");
    assert.deepStrictEqual(await q(L, "getTally", IP), { count: 1, k: 2, confirmed: false });
    await tx(L, B, "reportThreat", IP, "ja3x");
    assert.deepStrictEqual(await q(L, "getTally", IP), { count: 2, k: 2, confirmed: true });
    assert.ok(L.events.some((e) => e.name === "ThreatConsensusReached" && e.ip === IP));
    assert.strictEqual((await q(L, "blockInfo", IP)).active, true);
  });
  it("the same node cannot vote twice", async () => {
    const L = await setup(); await tx(L, A, "reportThreat", IP, "j");
    await rejects(tx(L, A, "reportThreat", IP, "j"), "already reported");
  });
  it("an unstaked or unknown caller cannot report", async () => {
    const L = await setup();
    await rejects(tx(L, X, "reportThreat", IP, "j"), "not staked");
  });
  it("a second report after the window is refused", async () => {
    const L = await setup(); await tx(L, A, "reportThreat", IP, "j");
    L.t += 61;
    await rejects(tx(L, B, "reportThreat", IP, "j"), "window expired");
  });
  it("an unconfirmed report is slashed after the window, not before", async () => {
    const L = await setup(); await tx(L, A, "reportThreat", IP, "j");
    await rejects(tx(L, C, "slashExpired", IP), "window still open");
    L.t += 61; await tx(L, C, "slashExpired", IP);
    assert.strictEqual((await q(L, "nodeInfo", id(A))).stake, 0);
    await rejects(tx(L, C, "slashExpired", IP), "already settled");
    await rejects(tx(L, B, "reportThreat", IP, "j"), "threat settled");
  });
  it("a confirmed threat cannot be slashed", async () => {
    const L = await setup(); await tx(L, A, "reportThreat", IP, "j"); await tx(L, B, "reportThreat", IP, "j");
    L.t += 100; await rejects(tx(L, C, "slashExpired", IP), "already confirmed");
  });
  it("failed transactions leave no trace", async () => {
    const L = await setup(); await tx(L, A, "reportThreat", IP, "j");
    await rejects(tx(L, A, "reportThreat", IP, "j"));
    assert.strictEqual((await q(L, "getTally", IP)).count, 1);
  });
});

describe("hardening: protected IPs, rate limit, quorum", () => {
  async function govern(L, who, kind, ip, node, value) { return tx(L, who, "propose", kind, ip, node, value); }
  it("a protected IP can never be reported", async () => {
    const L = await setup(); await govern(L, OWNER, 2, "10.0.0.1", "", 0);
    assert.strictEqual(JSON.parse(await tx(L, OWNER, "isProtected", "10.0.0.1")), true);
    await rejects(tx(L, A, "reportThreat", "10.0.0.1", "j"), "protected IP");
    await govern(L, OWNER, 3, "10.0.0.1", "", 0); await tx(L, A, "reportThreat", "10.0.0.1", "j");
  });
  it("per-node hourly report cap", async () => {
    const L = await setup(); await govern(L, OWNER, 10, "", "", 2);
    await tx(L, A, "reportThreat", "1.1.1.1", "j"); await tx(L, A, "reportThreat", "1.1.1.2", "j");
    await rejects(tx(L, A, "reportThreat", "1.1.1.3", "j"), "rate limit");
    L.t += 3600; await tx(L, A, "reportThreat", "1.1.1.3", "j");
  });
  it("quorum percentage raises the number of reports needed", async () => {
    const L = await setup();
    for (let i = 0; i < 2; i++) { const w = ["Org1MSP", "extra" + i]; await tx(L, OWNER, "addNode", id(w)); await tx(L, w, "registerNode"); }
    await govern(L, OWNER, 9, "", "", 100);                     // 5 nodes, 100% -> 5 reports
    assert.strictEqual((await q(L, "params")).required, 5);
    await tx(L, A, "reportThreat", IP, "j"); await tx(L, B, "reportThreat", IP, "j");
    assert.strictEqual((await q(L, "getTally", IP)).confirmed, false);
    await rejects(govern(L, OWNER, 9, "", "", 101), "percent");
  });
});

describe("multi-signature governance", () => {
  const G2 = ["Org2MSP", "Admin@org2"];
  async function threeGovernors() {
    const L = await setup();
    await tx(L, OWNER, "propose", 6, "", id(G2), 0);
    await tx(L, OWNER, "propose", 6, "", id(A), 0);
    await tx(L, OWNER, "propose", 8, "", "", 2);                // threshold 2 of 3
    return L;
  }
  it("with threshold 1 a proposal executes at once", async () => {
    const L = await setup(); await tx(L, OWNER, "propose", 6, "", id(G2), 0);
    assert.strictEqual((await q(L, "params")).govCount, 2);
  });
  it("with threshold 2 one signature is not enough, two are", async () => {
    const L = await threeGovernors();
    assert.strictEqual((await q(L, "params")).govThreshold, 2);
    await tx(L, A, "propose", 4, "", id(X), 0);                 // proposal 3, signed by A only
    assert.strictEqual(JSON.parse(await tx(L, OWNER, "nodeInfo", id(X))).approved, false);
    await tx(L, OWNER, "approve", 3);
    assert.strictEqual(JSON.parse(await tx(L, OWNER, "nodeInfo", id(X))).approved, true);
  });
  it("double signing, signing an executed proposal, and non-governors are refused", async () => {
    const L = await threeGovernors();
    await tx(L, A, "propose", 4, "", id(X), 0);
    await rejects(tx(L, A, "approve", 3), "already signed");
    await tx(L, OWNER, "approve", 3);
    await rejects(tx(L, G2, "approve", 3), "already executed");
    await rejects(tx(L, B, "propose", 4, "", id(X), 0), "governor only");
    await rejects(tx(L, B, "approve", 3), "governor only");
  });
  it("owner can no longer add nodes directly once the threshold is above 1", async () => {
    const L = await threeGovernors();
    await rejects(tx(L, OWNER, "addNode", id(X)), "owner only");
  });
  it("overrule cancels a confirmed block and slashes the reporters", async () => {
    const L = await setup(); await tx(L, A, "reportThreat", IP, "j"); await tx(L, B, "reportThreat", IP, "j");
    await tx(L, OWNER, "propose", 1, IP, "", 0);
    assert.strictEqual((await q(L, "blockInfo", IP)).active, false);
    assert.strictEqual((await q(L, "nodeInfo", id(A))).stake, 0);
    assert.ok(L.events.some((e) => e.name === "ThreatOverruled" && e.slashedNodes === 2));
    await rejects(tx(L, OWNER, "propose", 1, IP, "", 0), "nothing to overrule");
  });
  it("threshold must stay within 1..number of governors, and the last governors cannot be removed below it", async () => {
    const L = await setup();
    await rejects(tx(L, OWNER, "propose", 8, "", "", 5), "bad threshold");
    await rejects(tx(L, OWNER, "propose", 11, "", "", 0), "bad kind");
  });
});

describe("clean-state anchor", () => {
  it("a staked node anchors a root; anyone can read it", async () => {
    const L = await setup();
    await tx(L, A, "anchorCleanState", IP, ROOT, 1234567);
    assert.deepStrictEqual(await q(L, "getCleanState", IP), { merkleRoot: ROOT, tAttack: 1234567, anchored: true });
    assert.strictEqual((await q(L, "getCleanState", "9.9.9.9")).anchored, false);
  });
  it("unstaked callers and malformed roots are refused", async () => {
    const L = await setup();
    await rejects(tx(L, X, "anchorCleanState", IP, ROOT, 1), "not staked");
    await rejects(tx(L, A, "anchorCleanState", IP, "nothex", 1), "64 hex");
  });
});
