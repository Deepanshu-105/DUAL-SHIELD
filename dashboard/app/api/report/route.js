import { connection } from "next/server";
import { MULTI, agentLog } from "../../../lib/agent.js";
import { parseLine, summarize } from "../../../lib/events.js";
import { renderReport } from "../../../lib/report.js";

// v13.22: GET /api/report -> printable HTML incident report (needs a signed-in session like every /api call; proxy.js)
const SOURCES = ["web", "host", "nodewatch", "keeper"];
export async function GET() {
  await connection();
  const events = [];
  if (MULTI) {
    const jobs = [];
    for (const who of ["target", "peer"]) for (const name of SOURCES) jobs.push(agentLog(who, name, 200).then((lines) => ({ who, name, lines })));
    for (const g of await Promise.all(jobs)) for (const l of g.lines) { const e = parseLine(l, g.who === "target" ? "T" : "P", g.name); if (e) events.push(e); }
  }
  const html = renderReport(events, summarize(events), { generated: new Date().toLocaleString("en-GB") });
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'", "cache-control": "no-store" } });
}
