import fs from "fs";
import path from "path";
import { execSync } from "child_process";

function containerLines(name, file) {
  try {
    return execSync(`docker exec ${name} tail -20 ${file}`, { timeout: 3000 }).toString().split("\n");
  } catch { return []; }
}

export async function GET() {
  const ev = [];
  // Layer 2: ransomware detector (host file)
  let text = "";
  try { text = fs.readFileSync(path.join(process.cwd(), "..", "ransomware/evidence/watch.log"), "utf8"); } catch {}
  for (const l of text.split("\n").slice(-60)) {
    const m = l.match(/^(\d+\.\d+)\s+(FLAGGED|KILL_TRIGGER|KILLED)\s*(.*)$/);
    if (!m) continue;
    const label = m[2] === "FLAGGED" ? "File flagged: " + m[3].split(/\s+/).slice(2, 4).join(" ")
      : m[2] === "KILL_TRIGGER" ? "Kill rule triggered (" + m[3] + ")" : "Process killed (" + m[3] + ")";
    ev.push({ ts: Number(m[1]), layer: 2, kind: m[2], text: label });
  }
  // Layer 1: network blocks on target and peer (container files)
  for (const [name, file, re, verb] of [
    ["target", "/var/log/parser_block.log", /PARSER_BLOCK ip=(\S+) ts=([\d.]+)/, "Blocked on target"],
    ["peer", "/var/log/peer_block.log", /PEER_BLOCK ip=(\S+) ts=([\d.]+)/, "Immunised on peer"],
  ]) {
    for (const l of containerLines(name, file)) {
      const m = l.match(re);
      if (m) ev.push({ ts: Number(m[2]), layer: 1, kind: "BLOCK", text: verb + ": " + m[1] });
    }
  }
  ev.sort((a, b) => b.ts - a.ts);
  return Response.json(ev.slice(0, 20));
}
