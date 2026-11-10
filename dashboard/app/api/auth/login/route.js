import { checkPassword, issue, cookieHeader, clientIp, lockedFor, noteFail, noteOk, sameOrigin, audit, configured } from "../../../../lib/security.js";

export async function POST(req) {
  const ip = clientIp(req);
  if (!configured()) return Response.json({ ok: false, error: "dashboard not configured" }, { status: 503 });
  if (!sameOrigin(req)) { audit("CSRF_REFUSED", "-", ip, "login"); return Response.json({ ok: false, error: "refused" }, { status: 403 }); }
  const wait = lockedFor(ip);
  if (wait > 0) { audit("LOGIN_LOCKED", "-", ip, wait + "s"); return Response.json({ ok: false, error: "Too many attempts. Try again in " + wait + " s." }, { status: 429, headers: { "Retry-After": String(wait) } }); }
  const body = await req.json().catch(() => ({}));
  const pass = typeof body.password === "string" ? body.password.slice(0, 200) : "";
  const role = checkPassword(pass);
  if (!role) {
    noteFail(ip);
    await new Promise((r) => setTimeout(r, 600));          // slows guessing, the same for every wrong answer
    audit("LOGIN_FAIL", "-", ip, "wrong password");
    return Response.json({ ok: false, error: "Wrong password." }, { status: 401 });
  }
  noteOk(ip);
  audit("LOGIN_OK", role, ip, "");
  const s = issue(role);
  return Response.json({ ok: true, role }, { headers: { "Set-Cookie": cookieHeader(s.token, s.maxAge) } });
}
