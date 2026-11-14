import { NextResponse } from "next/server";
import { configured, sessionOf, issue, cookieHeader, clearCookie, securityHeaders, sameOrigin, audit, clientIp } from "./lib/security.js";

// v13: every page and every /api call needs a valid session (log in at /login). The only open doors are /login and POST /api/auth/login.
//   viewer: read-only (GET).  admin: may also POST, but only same-origin and with the x-ds-confirm header.
// DASH_AUTH=off still switches everything off for the old open lab mode (not for demonstrations to an evaluator).
export function proxy(request) {
  const { pathname } = request.nextUrl;
  const done = (res) => { securityHeaders(res.headers); if (pathname.startsWith("/api/")) res.headers.set("Cache-Control", "no-store"); return res; };
  if (process.env.DASH_AUTH === "off") return done(NextResponse.next());
  if (!configured()) return done(new NextResponse("Dashboard locked: set DASH_PASS (at least 8 characters) in multi/config.env.", { status: 503 }));

  const open = pathname === "/login" || (pathname === "/api/auth/login" && request.method === "POST");
  const sess = sessionOf(request);
  if (open) return done(NextResponse.next());

  if (!sess) {
    if (pathname.startsWith("/api/")) return done(NextResponse.json({ ok: false, error: "login required" }, { status: 401 }));
    const res = NextResponse.redirect(new URL("/login", request.url));
    res.headers.append("Set-Cookie", clearCookie());
    return done(res);
  }
  if (request.method !== "GET" && request.method !== "HEAD" && pathname !== "/api/auth/logout") {   // any signed-in role may sign out
    if (sess.r !== "admin") { audit("DENIED", sess.r, clientIp(request), request.method + " " + pathname); return done(NextResponse.json({ ok: false, error: "read-only account" }, { status: 403 })); }
    if ((!sameOrigin(request) || request.headers.get("x-ds-confirm") !== "1")) {
      audit("CSRF_REFUSED", sess.r, clientIp(request), pathname);
      return done(NextResponse.json({ ok: false, error: "cross-site or unconfirmed request refused" }, { status: 403 }));
    }
  }
  const res = NextResponse.next();
  const now = Math.floor(Date.now() / 1000);
  if (now - sess.i > 60) { const n = issue(sess.r, sess); res.headers.append("Set-Cookie", cookieHeader(n.token, n.maxAge)); }   // sliding idle timeout
  return done(res);
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"] };
