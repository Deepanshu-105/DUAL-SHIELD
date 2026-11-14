import { connection } from "next/server";
import { execSync } from "child_process";
import { MULTI, agent } from "../../../lib/agent.js";

export async function GET() {
  await connection();   // never prerendered or cached at build time: always live data
  const out = {};
  for (const n of ["target", "peer"]) {
    try {
      if (MULTI) {
        out[n] = (await agent(n, "/ipset")).ips;          // four-laptop mode: ask the agent
        continue;
      }
      const t = execSync(`docker exec ${n} ipset list city_blacklist`, { timeout: 3000 }).toString();
      out[n] = t.split("\n").filter(l => /^\d+\.\d+\.\d+\.\d+/.test(l)).map(l => l.trim().split(/\s+/)[0]);
    } catch {
      out[n] = null;   // container not running / agent not reachable
    }
  }
  return Response.json(out);
}
