"use strict";
/*
 * CityShield gateway (runs on D next to the Fabric network). The other laptops cannot talk to Fabric directly (the Fabric ports
 * listen on 127.0.0.1); they call this small API and every call is made with a Fabric identity chosen by the caller's certificate:
 *
 *   POST /tx     {"who":1,"fn":"reportThreat","args":["1.2.3.4","fp"]}  -> endorsed by both organisations, ordered, committed
 *   POST /query  {"who":0,"fn":"getTally","args":["1.2.3.4"]}           -> read only
 *   GET  /events?after=<id>                                             -> chaincode events since id (polling, survives restarts)
 *   GET  /health
 *
 * Identities ("who"): 0 Org1 Admin (owner), 1 Org1 User1 (target node), 2 Org2 User1 (peer node), 3 Org1 User2, 4 Org2 User2, 5 Org2 Admin.
 * With GATEWAY_TLS=1 the API is HTTPS with mutual TLS (private CA, multi/make_tls.sh) and each role may only use its own identity:
 *   dualshield-dashboard -> 0,3,4,5   dualshield-target -> 1   dualshield-peer -> 2
 * GATEWAY_LAB=1 lets any authenticated laptop use any identity (the lab demo has the target report "as the peer" to reach K=2).
 */
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const grpc = require("@grpc/grpc-js");
const { connect, signers, hash } = require("@hyperledger/fabric-gateway");

const FAB = path.resolve(__dirname, "..");
const NET = process.env.FABRIC_NET || path.join(FAB, "network");
const CH = process.env.FABRIC_CHANNEL || "cityshield", CC = process.env.FABRIC_CHAINCODE || "cityshield";
const PORT = Number(process.env.GATEWAY_PORT || 8600), HOST = process.env.GATEWAY_HOST || "0.0.0.0";
const TLS = process.env.GATEWAY_TLS === "1" || process.env.TLS === "1", LAB = process.env.GATEWAY_LAB === "1";
const EVFILE = process.env.GATEWAY_EVENTS || path.join(NET, "events.jsonl");
const O = (n) => path.join(NET, "crypto", "peerOrganizations", `org${n}.example.com`);
const IDENT = [[1, "Admin"], [1, "User1"], [2, "User1"], [1, "User2"], [2, "User2"], [2, "Admin"]].map(([org, u]) => ({
  mspId: `Org${org}MSP`, name: `${u}@org${org}.example.com`, dir: path.join(O(org), "users", `${u}@org${org}.example.com`, "msp"),
}));
const ALLOWED = { "dualshield-dashboard": [0, 3, 4, 5], "dualshield-target": [1], "dualshield-peer": [2] };
const readFirst = (d) => fs.readFileSync(path.join(d, fs.readdirSync(d).filter((f) => !f.startsWith("."))[0]));

const peerTls = fs.readFileSync(path.join(O(1), "peers", "peer0.org1.example.com", "tls", "ca.crt"));
const client = new grpc.Client(process.env.FABRIC_PEER || "127.0.0.1:7051", grpc.credentials.createSsl(peerTls), { "grpc.ssl_target_name_override": "peer0.org1.example.com" });
const conns = new Map();
function contractFor(who) {
  if (!conns.has(who)) {
    const id = IDENT[who];
    const gw = connect({
      client, hash: hash.sha256,
      identity: { mspId: id.mspId, credentials: readFirst(path.join(id.dir, "signcerts")) },
      signer: signers.newPrivateKeySigner(crypto.createPrivateKey(readFirst(path.join(id.dir, "keystore")))),
      evaluateOptions: () => ({ deadline: Date.now() + 5000 }), endorseOptions: () => ({ deadline: Date.now() + 15000 }),
      submitOptions: () => ({ deadline: Date.now() + 5000 }), commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });
    conns.set(who, { gw, network: gw.getNetwork(CH), contract: gw.getNetwork(CH).getContract(CC) });
  }
  return conns.get(who);
}
const dec = (b) => Buffer.from(b).toString("utf8");

// ---- events: persisted so that a restart or a slow poller never loses one. id = block * 10000 + position in block
let events = [], lastId = 0;
function loadEvents() {
  try {
    for (const ln of fs.readFileSync(EVFILE, "utf8").split("\n")) if (ln.trim()) { const e = JSON.parse(ln); events.push(e); lastId = Math.max(lastId, e.id); }
  } catch { /* first start */ }
  events = events.slice(-5000);
}
async function eventLoop() {
  for (;;) {
    try {
      const { network } = contractFor(0);
      const start = BigInt(Math.floor(lastId / 10000));
      let curBlock = -1, seq = 0;
      for await (const ev of await network.getChaincodeEvents(CC, { startBlock: start })) {
        const block = Number(ev.blockNumber);
        if (block !== curBlock) { curBlock = block; seq = 0; }
        let list = [];
        try { list = JSON.parse(dec(ev.payload)); } catch { continue; }
        for (const e of list) {
          const id = block * 10000 + seq++;
          if (id <= lastId) continue;
          lastId = id;
          const rec = { id, block, tx: ev.transactionId, ...e };
          events.push(rec); if (events.length > 5000) events.shift();
          fs.appendFileSync(EVFILE, JSON.stringify(rec) + "\n");
        }
      }
    } catch (e) { console.error("event stream:", e.message, "- retrying in 2 s"); }
    await new Promise((r) => setTimeout(r, 2000));
  }
}

// ---- HTTP API
function allowed(req, who) {
  if (!TLS || LAB) return true;
  const cn = req.socket.getPeerCertificate && (req.socket.getPeerCertificate().subject || {}).CN;
  return (ALLOWED[cn] || []).includes(who);
}
function body(req) {
  return new Promise((res, rej) => {
    const ch = []; let n = 0;
    req.on("data", (c) => { n += c.length; if (n > 65536) { rej(new Error("body too large")); req.destroy(); } else ch.push(c); });
    req.on("end", () => { try { res(JSON.parse(Buffer.concat(ch).toString() || "{}")); } catch (e) { rej(e); } });
  });
}
const send = (res, code, obj) => { const b = JSON.stringify(obj); res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) }); res.end(b); };
const FN = /^[A-Za-z][A-Za-z0-9_]{0,40}$/;

async function handler(req, res) {
  try {
    const u = new URL(req.url, "http://x");
    if (req.method === "GET" && u.pathname === "/health") return send(res, 200, { ok: true, head: lastId, tls: TLS });
    if (req.method === "GET" && u.pathname === "/events") {
      const after = Number(u.searchParams.get("after") || 0), limit = Math.min(Number(u.searchParams.get("limit") || 500), 2000);
      return send(res, 200, { head: lastId, events: events.filter((e) => e.id > after).slice(0, limit) });
    }
    if (req.method === "POST" && (u.pathname === "/tx" || u.pathname === "/query")) {
      const b = await body(req), who = Number(b.who);
      if (!Number.isInteger(who) || !IDENT[who]) return send(res, 400, { ok: false, error: "unknown identity" });
      if (!allowed(req, who)) return send(res, 403, { ok: false, error: "this certificate may not use that identity" });
      if (!FN.test(String(b.fn)) || !Array.isArray(b.args) || b.args.some((a) => typeof a !== "string" && typeof a !== "number")) return send(res, 400, { ok: false, error: "bad request" });
      const { contract } = contractFor(who), args = b.args.map(String);
      const out = u.pathname === "/tx" ? await contract.submitTransaction(b.fn, ...args) : await contract.evaluateTransaction(b.fn, ...args);
      return send(res, 200, { ok: true, result: dec(out) });
    }
    return send(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    const msg = (e.details && e.details[0] && e.details[0].message) || e.message || String(e);
    return send(res, 500, { ok: false, error: msg.replace(/^.*message:/, "").trim().slice(0, 300) });
  }
}

function main() {
  loadEvents();
  let srv;
  if (TLS) {
    const d = process.env.TLS_DIR || path.join(FAB, "..", "multi", "tls", "dashboard");
    srv = https.createServer({ key: fs.readFileSync(path.join(d, "node.key")), cert: fs.readFileSync(path.join(d, "node.crt")), ca: fs.readFileSync(path.join(d, "ca.crt")),
      requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.2" }, handler);
  } else srv = http.createServer(handler);
  srv.listen(PORT, HOST, () => console.log(`GATEWAY_UP :${PORT} ${TLS ? "mutual TLS" : "plain HTTP (lab)"}${LAB ? " lab identities" : ""} channel=${CH} chaincode=${CC}`));
  eventLoop();
}
if (require.main === module) main();
module.exports = { IDENT, ALLOWED };
