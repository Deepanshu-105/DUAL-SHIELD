import fs from "fs";
import path from "path";
import { MULTI, agentLog } from "../../../lib/agent.js";

export async function GET() {
  let text = "";
  if (MULTI) {
    text = (await agentLog("target", "watch", 500)).join("\n");   // watch.log lives on laptop T
  } else {
    const log = path.join(process.cwd(), "..", "ransomware/evidence/watch.log");
    try { text = fs.readFileSync(log, "utf8"); } catch {}
  }
  const lines = text.split("\n");
  const files = new Set(
    lines.filter(l => l.includes(" FLAGGED ")).map(l => l.split(/\s+/)[4])
  );
  const kills = lines.filter(l => l.includes(" KILLED pid=")).length;
  return Response.json({ flagged: files.size, kills });
}
