import { MULTI, agent } from "../../../../lib/agent.js";
import { needAdmin, audit } from "../../../../lib/security.js";

// Demonstration controls (administrator, audited). DEMO_MODE=0 removes them for a real deployment.
export async function POST(req) {
  const { w, deny } = needAdmin(req); if (deny) return deny;
  if (process.env.DEMO_MODE === "0") return Response.json({ ok: false, error: "demo controls are disabled (DEMO_MODE=0)" }, { status: 403 });
  const b = await req.json().catch(() => ({}));
  if (b.action !== "ransomware") return Response.json({ ok: false, error: "unknown action" }, { status: 400 });
  if (!MULTI) return Response.json({ ok: false, error: "needs MULTI=1 (agents on T and P)" });
  try {
    const r = await agent("target", "/ransomware", { method: "POST", body: "{}", timeout: 20000 });
    audit("DEMO_RANSOMWARE", w.name, w.ip, r.output || "");
    return Response.json({ ok: !!r.ok, output: r.output || "" });
  } catch (e) { return Response.json({ ok: false, output: "target agent not reachable: " + e.message }); }
}
