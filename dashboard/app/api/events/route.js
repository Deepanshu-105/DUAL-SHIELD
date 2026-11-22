import { connection } from "next/server";
import { MULTI, agentLog } from "../../../lib/agent.js";
import { parseLine, summarize } from "../../../lib/events.js";

// v13.21: attack events of the newer guards (web, host, node watch, block keeper) from T and P. Empty until those guards run (v13.16+ / v13.19 / v13.20).
const SOURCES = ["web", "host", "nodewatch", "keeper"];
export async function GET() {
  await connection();
  if (!MULTI) return Response.json({ multi: false, events: [], counts: null });
  const jobs = [];
  for (const who of ["target", "peer"]) for (const name of SOURCES) jobs.push(agentLog(who, name, 80).then((lines) => ({ who, name, lines })));
  const got = await Promise.all(jobs);
  const events = [];
  for (const g of got) for (const l of g.lines) { const e = parseLine(l, g.who === "target" ? "T" : "P", g.name); if (e) events.push(e); }
  events.sort((a, b) => b.ts - a.ts);
  return Response.json({ multi: true, events: events.slice(0, 150), counts: summarize(events) });
}
