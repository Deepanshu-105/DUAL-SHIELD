import { NextResponse } from "next/server";
import { pathAllowed, configured, sessionOf, issue, cookieHeader, clearCookie, securityHeaders, sameOrigin, audit, clientIp } from "./lib/security.js";

// v13: every page and every /api call needs a valid session (log in at /login). The only open doors are /login and POST /api/auth/login.
//   viewer: read-only (GET).  operator: Layer 2 actions.  admin: may also POST everything, but only same-origin and with the x-ds-confirm header.
// DASH_AUTH=off still switches everything off for the old open lab mode (not for demonstrations to an evaluator).
// v13.4: a fresh nonce per request. Scripts run only if they carry it (no more 'unsafe-inline' for scripts); Next.js reads the nonce from the
// request's CSP header and stamps its own scripts. DASH_CSP_NONCE=0 returns to the old policy if a browser or extension misbehaves.
const ADMIN_ONLY = ["/api/admin/chain", "/api/audit"];     // operator may run Layer 2 actions and the demo, but not governance or the audit log
// v13.5: flood protection for the console itself. Requests WITHOUT a valid session share a small budget per client address (all clients look the same
// behind the TLS tunnel unless DASH_TRUST_PROXY=1 gives real addresses), so a flood of anonymous requests is refused cheaply while signed-in
// operators keep working; a signed-in session has its own, larger budget (a stolen cookie cannot hammer the server either).
const RATE_ANON = Number(process.env.DASH_RATE_ANON || 120), RATE_SESSION = Number(process.env.DASH_RATE_SESSION || 1500);   // requests per minute
function overLimit(key, max) {
  const R = (globalThis.__dsrl ||= { m: new Map(), warned: 0 }), now = Date.now();
  let e = R.m.get(key);
  if (!e || now - e.t0 > 60000) { e = { t0: now, n: 0 }; R.m.set(key, e); if (R.m.size > 5000) R.m.clear(); }
  e.n++;
  return e.n > max ? Math.ceil((e.t0 + 60000 - now) / 1000) : 0;
}
export function proxy(request) {
  const { pathname } = request.nextUrl;
  const nonce = process.env.DASH_CSP_NONCE === "0" ? "" : Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64");
  const next = () => {
    if (!nonce) return NextResponse.next();
    const rh = new Headers(request.headers); rh.set("x-nonce", nonce);
    const tmp = securityHeaders(new Headers(), nonce); rh.set("content-security-policy", tmp.get("content-security-policy"));
    return NextResponse.next({ request: { headers: rh } });
  };
  const done = (res) => { securityHeaders(res.headers, nonce); if (pathname.startsWith("/api/")) res.headers.set("Cache-Control", "no-store"); return res; };
  if (process.env.DASH_AUTH === "off") return done(next());
  if (!configured()) return done(new NextResponse("Dashboard locked: set DASH_PASS (at least 8 characters) in multi/config.env.", { status: 503 }));

  const sess0 = sessionOf(request);
  const wait = overLimit(sess0 ? "s:" + sess0.s : "a:" + clientIp(request), sess0 ? RATE_SESSION : RATE_ANON);
  if (wait) {
    const R = globalThis.__dsrl; if (Date.now() - R.warned > 60000) { R.warned = Date.now(); audit("RATE_LIMITED", sess0 ? sess0.r : "-", clientIp(request), (sess0 ? "session" : "anonymous") + " requests over the limit"); }
    return done(new NextResponse("Too many requests", { status: 429, headers: { "Retry-After": String(wait) } }));
  }
  const open = pathname === "/login" || (pathname === "/api/auth/login" && request.method === "POST");
  const sess = sessionOf(request);
  if (open) return done(next());

  if (!sess) {
    if (pathname.startsWith("/api/")) return done(NextResponse.json({ ok: false, error: "login required" }, { status: 401 }));
    const res = NextResponse.redirect(new URL("/login", request.url));
    res.headers.append("Set-Cookie", clearCookie());
    return done(res);
  }
  if (request.method !== "GET" && request.method !== "HEAD" && pathname !== "/api/auth/logout") {   // any signed-in role may sign out
    if (!pathAllowed(sess.r, pathname, request.method)) { audit("DENIED", sess.r, clientIp(request), request.method + " " + pathname); return done(NextResponse.json({ ok: false, error: sess.r === "viewer" ? "read-only account" : "administrator role required" }, { status: 403 })); }
    if ((!sameOrigin(request) || request.headers.get("x-ds-confirm") !== "1")) {
      audit("CSRF_REFUSED", sess.r, clientIp(request), pathname);
      return done(NextResponse.json({ ok: false, error: "cross-site or unconfirmed request refused" }, { status: 403 }));
    }
  }
  const res = next();
  const now = Math.floor(Date.now() / 1000);
  if (now - sess.i > 60) { const n = issue(sess.r, sess); res.headers.append("Set-Cookie", cookieHeader(n.token, n.maxAge)); }   // sliding idle timeout
  return done(res);
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"] };
