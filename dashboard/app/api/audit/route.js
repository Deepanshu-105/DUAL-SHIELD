import { who, readAudit } from "../../../lib/security.js";
// administrator only: the audit trail with a check that nobody edited or removed a line (each line holds the hash of the one before).
export async function GET(req) {
  if (who(req).role !== "admin") return Response.json({ ok: false, error: "administrator role required" }, { status: 403 });
  return Response.json({ ok: true, ...readAudit(80) });
}
