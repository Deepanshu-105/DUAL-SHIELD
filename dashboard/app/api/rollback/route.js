import { execFileSync } from "child_process";
import path from "path";

// POST /api/rollback  {ip?}  -> restores data/sample_copy from the clean snapshot,
// but only if its Merkle root matches the root anchored on-chain for that IP.
export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(body.ip || "") ? body.ip : "172.30.0.12";
  const root = path.join(process.cwd(), "..");
  const py = path.join(root, "blockchain", ".venv", "bin", "python3");
  const t0 = Date.now();
  try {
    const out = execFileSync(py, ["rollback.py", "restore", "data/sample_copy", "--anchor", ip], {
      cwd: path.join(root, "ransomware"), encoding: "utf8", timeout: 60000,
    });
    return Response.json({ ok: true, ip, ms: Date.now() - t0, output: out });
  } catch (e) {
    return Response.json({ ok: false, ip, ms: Date.now() - t0, output: (e.stdout || "") + (e.stderr || e.message) });
  }
}
