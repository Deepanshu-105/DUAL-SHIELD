import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { MULTI, agent } from "../../../lib/agent.js";
import { needAdmin, audit } from "../../../lib/security.js";

// Recovery panel data (Layer 2 recovery): vault, guard, containment, last recovery.
//   GET  /api/recovery                         -> summary (four-laptop mode: asked from laptop T's agent)
//   POST /api/recovery {action:"recover"|"unfreeze"}  -> needs the x-ds-confirm header (same rule as rollback)
const root = path.join(process.cwd(), "..");
const rdir = path.join(root, "ransomware");
const venv = path.join(root, "blockchain", ".venv", "bin", "python3");
const py = fs.existsSync(venv) ? venv : "python3";
const local = (args) => execFileSync(py, args, { cwd: rdir, encoding: "utf8", timeout: 120000 });

export async function GET() {
  try {
    if (MULTI) return Response.json({ ...(await agent("target", "/recovery")), via: "agent" });
    return Response.json({ ...JSON.parse(local(["vault.py", "summary"])), via: "local" });
  } catch (e) {
    return Response.json({ available: false, error: String(e.message || e).slice(0, 200) });
  }
}

export async function POST(req) {
  if (req.headers.get("x-ds-confirm") !== "1") {
    return Response.json({ ok: false, output: "missing x-ds-confirm header" }, { status: 403 });
  }
  const body = await req.json().catch(() => ({}));
  const action = body.action;
  if (action !== "recover" && action !== "unfreeze") {
    return Response.json({ ok: false, output: "unknown action" }, { status: 400 });
  }
  const t0 = Date.now();
  audit("RECOVERY_" + action.toUpperCase(), w.name, w.ip, "requested");
  try {
    if (MULTI) {
      const ip = process.env.ATTACKER_IP || "";
      const r = await agent("target", "/" + action, {
        method: "POST", body: JSON.stringify(action === "recover" && ip ? { ip } : {}), timeout: 120000,
      });
      return Response.json({ ok: !!r.ok, ms: Date.now() - t0, output: r.output || "" });
    }
    const out = action === "recover"
      ? local(["recover.py", "sample", "data/sample_copy", "--in-place"])
      : local(["vault.py", "unfreeze"]);
    return Response.json({ ok: true, ms: Date.now() - t0, output: out });
  } catch (e) {
    return Response.json({ ok: false, ms: Date.now() - t0, output: (e.stdout || "") + (e.stderr || e.message) });
  }
}
