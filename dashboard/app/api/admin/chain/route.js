import { call, q, tx } from "../../../../lib/gateway.js";
import { needAdmin, audit, validIp, validNode } from "../../../../lib/security.js";

// Governance and consensus view. GET: any logged-in role. POST: administrator (propose / approve), validated and audited.
const WARMUP = "203.0.113.1";
const KINDS = { 1: "Overrule a confirmed threat (slash its reporters)", 2: "Protect an IP", 3: "Unprotect an IP", 4: "Approve a node", 5: "Revoke a node",
  6: "Add a governor", 7: "Remove a governor", 8: "Set governor threshold", 9: "Set quorum percent", 10: "Set reports-per-hour limit" };
const NODES = ["Org1MSP:User1@org1.example.com", "Org2MSP:User1@org2.example.com", "Org1MSP:User2@org1.example.com"];

export async function GET() {
  try {
    const params = await q("params");
    const count = Number(await q("proposalCount"));
    const proposals = [];
    for (let id = Math.max(0, count - 12); id < count; id++) { try { proposals.push({ id, ...(await q("getProposal", String(id))) }); } catch {} }
    const evs = (await call("GET", "/events?after=0&limit=2000")).events.filter((e) => e.ip !== WARMUP);
    const ips = [...new Set(evs.filter((e) => e.name === "ThreatReported").map((e) => e.ip))].slice(-6);
    const tallies = await Promise.all(ips.map(async (ip) => ({ ip, ...(await q("getTally", ip)), ...(await q("blockInfo", ip)) })));
    const nodes = await Promise.all(NODES.map(async (n) => ({ addr: n, ...(await q("nodeInfo", n)) })));
    return Response.json({ ok: true, params, kinds: KINDS, proposals: proposals.reverse(), tallies, nodes, events: evs.slice(-40).reverse() });
  } catch (e) { return Response.json({ ok: false, error: String(e.message || e).slice(0, 200) }); }
}

export async function POST(req) {
  const { w, deny } = needAdmin(req); if (deny) return deny;
  const b = await req.json().catch(() => ({}));
  try {
    if (b.action === "propose") {
      const kind = Number(b.kind);
      if (!Number.isInteger(kind) || kind < 1 || kind > 10) return Response.json({ ok: false, error: "bad kind" }, { status: 400 });
      const ip = b.ip ? String(b.ip) : "", node = b.node ? String(b.node) : "", value = b.value === undefined || b.value === "" ? 0 : Number(b.value);
      if ([1, 2, 3].includes(kind) && !validIp(ip)) return Response.json({ ok: false, error: "valid IP address needed" }, { status: 400 });
      if ([4, 5, 6, 7].includes(kind) && !validNode(node)) return Response.json({ ok: false, error: "node id like Org1MSP:User1@org1.example.com needed" }, { status: 400 });
      if (!Number.isInteger(value) || value < 0 || value > 1000) return Response.json({ ok: false, error: "value 0..1000" }, { status: 400 });
      const r = await tx("propose", String(kind), ip, node, String(value));
      audit("GOV_PROPOSE", w.name, w.ip, `kind=${kind} ip=${ip} node=${node} value=${value} -> id ${r && r.id}`);
      return Response.json({ ok: true, result: r });
    }
    if (b.action === "approve") {
      const id = Number(b.id);
      if (!Number.isInteger(id) || id < 0 || id > 1e6) return Response.json({ ok: false, error: "bad id" }, { status: 400 });
      await tx("approve", String(id));
      audit("GOV_APPROVE", w.name, w.ip, "proposal " + id);
      return Response.json({ ok: true });
    }
    return Response.json({ ok: false, error: "unknown action" }, { status: 400 });
  } catch (e) {
    audit("GOV_ERROR", w.name, w.ip, String(e.message || e));
    return Response.json({ ok: false, error: String(e.message || e).slice(0, 200) });
  }
}
