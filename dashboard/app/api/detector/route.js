import fs from "fs";
import path from "path";

export async function GET() {
  const log = path.join(process.cwd(), "..", "ransomware/evidence/watch.log");
  let text = "";
  try { text = fs.readFileSync(log, "utf8"); } catch {}
  const lines = text.split("\n");
  const files = new Set(
    lines.filter(l => l.includes(" FLAGGED ")).map(l => l.split(/\s+/)[4])
  );
  const kills = lines.filter(l => l.includes(" KILLED pid=")).length;
  return Response.json({ flagged: files.size, kills });
}
