import { execSync } from "child_process";

export async function GET() {
  const out = {};
  for (const n of ["target", "peer"]) {
    try {
      const t = execSync(`docker exec ${n} ipset list city_blacklist`, { timeout: 3000 }).toString();
      out[n] = t.split("\n").filter(l => /^\d+\.\d+\.\d+\.\d+/.test(l)).map(l => l.trim().split(/\s+/)[0]);
    } catch {
      out[n] = null;   // container not running
    }
  }
  return Response.json(out);
}
