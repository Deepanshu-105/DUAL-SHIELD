import { NextResponse } from "next/server";

// v2: the whole dashboard (page and /api/*) needs the operator password (HTTP Basic, user "operator").
// Set DASH_PASS before starting. For the old open lab mode set DASH_AUTH=off explicitly.
// (v9: no contract file any more; the chain is Hyperledger Fabric, read through /api/chain.)
const same = (a, b) => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};

export function proxy(request) {
  if (process.env.DASH_AUTH === "off") return NextResponse.next();
  const pass = process.env.DASH_PASS || "";
  if (pass.length < 8) {
    return new NextResponse("Dashboard locked: set DASH_PASS (at least 8 characters) in multi/config.env.", { status: 503 });
  }
  const h = request.headers.get("authorization") || "";
  if (h.startsWith("Basic ")) {
    let user = "", given = "";
    try { [user, given] = atob(h.slice(6)).split(/:(.*)/s); } catch {}
    if (same(user || "", "operator") && same(given || "", pass)) return NextResponse.next();
  }
  return new NextResponse("Operator login required", {
    status: 401, headers: { "WWW-Authenticate": 'Basic realm="Dual-Shield operator"' },
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"],
};
