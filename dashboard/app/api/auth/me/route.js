import { sessionOf } from "../../../../lib/security.js";
export async function GET(req) {
  const t = sessionOf(req);
  if (!t) return Response.json({ ok: false }, { status: 401 });
  return Response.json({ ok: true, role: t.r, expiresIn: t.e - Math.floor(Date.now() / 1000), maxIn: t.a - Math.floor(Date.now() / 1000) });
}
