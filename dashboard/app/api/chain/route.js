import { call, q } from "../../../lib/gateway.js";

// Live state of the CityShield chaincode on Hyperledger Fabric, read through the gateway on this laptop (fabric/gateway/server.js).
// Replaces the old browser-side Hardhat/ethers calls. Fabric has no gas and no ETH: "stake" is a plain counter in the chaincode.
const WARMUP = "203.0.113.1";   // start-up warm-up report, not a real attack
const NODES = ["Org1MSP:User1@org1.example.com", "Org2MSP:User1@org2.example.com", "Org1MSP:User2@org1.example.com"];


export async function GET() {
  try {
    const p = await q("params");
    const all = (await call("GET", "/events?after=0&limit=2000")).events;
    const slashed = new Set(all.filter((e) => e.name === "NodeSlashed" || e.name === "NodeRevoked").map((e) => e.node));
    const evs = all.filter((e) => e.name === "ThreatReported" && e.ip !== WARMUP);
    const ip = evs.length ? evs[evs.length - 1].ip : null;
    const t = ip ? await q("getTally", ip) : { count: 0, k: p.required, confirmed: false };
    const reporters = new Set(evs.filter((e) => e.ip === ip).map((e) => e.node));
    const nodes = await Promise.all(NODES.map(async (a) => ({ addr: a, stake: (await q("nodeInfo", a)).stake, reported: reporters.has(a), slashed: slashed.has(a) })));
    return Response.json({ status: "live", k: p.required, n: p.nodeCount, ip, count: t.count, confirmed: t.confirmed, nodes });
  } catch (e) {
    return Response.json({ status: "error: " + (e.message || e) });
  }
}
