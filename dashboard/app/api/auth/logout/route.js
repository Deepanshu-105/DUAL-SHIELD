import { sameOrigin, sessionOf, revoke, clearCookie, audit, clientIp } from "../../../../lib/security.js";
export async function POST(req) {
  if (!sameOrigin(req)) return Response.json({ ok: false }, { status: 403 });
  const t = sessionOf(req);
  if (t) { revoke(t); audit("LOGOUT", t.r, clientIp(req), ""); }
  return Response.json({ ok: true }, { headers: { "Set-Cookie": clearCookie() } });
}
