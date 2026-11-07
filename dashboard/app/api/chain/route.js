import fs from "fs";
import path from "path";
import http from "http";
import https from "https";

// Live state of the CityShield chaincode on Hyperledger Fabric, read through the gateway on this laptop (fabric/gateway/server.js).
// Replaces the old browser-side Hardhat/ethers calls. Fabric has no gas and no ETH: "stake" is a plain counter in the chaincode.
const WARMUP = "203.0.113.1";   // start-up warm-up report, not a real attack
const TLS = process.env.TLS === "1";
const GW = process.env.GATEWAY_URL || `${TLS ? "https" : "http"}://127.0.0.1:${process.env.GATEWAY_PORT || 8600}`;
const TLS_DIR = process.env.TLS_DIR || path.join(process.cwd(), "..", "multi", "tls", "dashboard");
const NODES = ["Org1MSP:User1@org1.example.com", "Org2MSP:User1@org2.example.com", "Org1MSP:User2@org1.example.com"];

function call(method, p, obj) {
  return new Promise((resolve, reject) => {
    const u = new URL(GW + p), body = obj ? JSON.stringify(obj) : null;
    const opt = { host: u.hostname, port: u.port, path: u.pathname + u.search, method, timeout: 8000,
      headers: body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {} };
    let mod = http;
    if (TLS) {
      mod = https;
      Object.assign(opt, { ca: fs.readFileSync(path.join(TLS_DIR, "ca.crt")), cert: fs.readFileSync(path.join(TLS_DIR, "node.crt")),
        key: fs.readFileSync(path.join(TLS_DIR, "node.key")), minVersion: "TLSv1.2", rejectUnauthorized: true, checkServerIdentity: () => undefined });
    }
    const r = mod.request(opt, (res) => {
      const ch = []; res.on("data", (c) => ch.push(c));
      res.on("end", () => { try { const o = JSON.parse(Buffer.concat(ch).toString()); o.ok === false ? reject(new Error(o.error)) : resolve(o); } catch (e) { reject(e); } });
    });
    r.on("error", reject); r.on("timeout", () => r.destroy(new Error("gateway timeout")));
    if (body) r.write(body);
    r.end();
  });
}
const q = async (fn, ...args) => JSON.parse((await call("POST", "/query", { who: 0, fn, args })).result);

export async function GET() {
  try {
    const p = await q("params");
    const evs = (await call("GET", "/events?after=0&limit=2000")).events.filter((e) => e.name === "ThreatReported" && e.ip !== WARMUP);
    const ip = evs.length ? evs[evs.length - 1].ip : null;
    const t = ip ? await q("getTally", ip) : { count: 0, k: p.required, confirmed: false };
    const reporters = new Set(evs.filter((e) => e.ip === ip).map((e) => e.node));
    const nodes = await Promise.all(NODES.map(async (a) => ({ addr: a, stake: (await q("nodeInfo", a)).stake, reported: reporters.has(a) })));
    return Response.json({ status: "live", k: p.required, n: p.nodeCount, ip, count: t.count, confirmed: t.confirmed, nodes });
  } catch (e) {
    return Response.json({ status: "error: " + (e.message || e) });
  }
}
