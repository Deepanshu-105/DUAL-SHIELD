import { discovered } from "../../../lib/agent.js";

// Registered laptops (discovery mode): who joined, from which address, and whether the heartbeat is fresh.
export async function GET() {
  const d = discovered();
  if (!d) return Response.json({ discovery: process.env.DISCOVERY === "1", peers: {} });
  const peers = {};
  for (const [role, p] of Object.entries(d)) peers[role] = { ip: p.ip, name: p.name || "", online: p.online, age: p.age };
  return Response.json({ discovery: true, peers });
}
