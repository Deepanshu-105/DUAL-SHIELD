// Dual-Shield dashboard security core (v13). Node runtime only (used by proxy.js and the route handlers).
//  * login with two roles: admin (DASH_PASS) and optional read-only viewer (DASH_VIEW_PASS)
//  * stateless HMAC-signed session cookie: HttpOnly, SameSite=Strict, short idle timeout, absolute maximum, revocable on logout
//  * login lockout with exponential back-off (per client and global), constant-time password checks
//  * same-origin check for every state-changing request, hash-chained audit log
import crypto from "crypto";
import fs from "fs";
import path from "path";

export const COOKIE = "ds_session";
const IDLE_S = Number(process.env.DASH_IDLE_S || 1800);       // logged out after 30 minutes without use
const MAX_S = Number(process.env.DASH_MAX_S || 8 * 3600);     // and never later than 8 hours after login
export const SECURE = process.env.TLS === "1" || process.env.DASH_SECURE_COOKIE === "1";

const g = globalThis;
g.__ds ||= { revoked: new Set(), fails: new Map(), auditPrev: null };
const S = g.__ds;

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const KEY = () => sha("ds-session-v13|" + (process.env.DASH_SESSION_KEY || "") + "|" + (process.env.DASH_PASS || "") + "|" + (process.env.DASH_VIEW_PASS || ""));
const b64 = (b) => Buffer.from(b).toString("base64url");
const mac = (data) => crypto.createHmac("sha256", KEY()).update(data).digest("base64url");
export const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));   // equal-length digests, constant time

export function configured() { return String(process.env.DASH_PASS || "").length >= 8; }

// roles: admin (everything), operator (Layer 2 actions and the demo, but no governance, no audit log), viewer (read only)
export function checkPassword(given) {
  const admin = process.env.DASH_PASS || "", view = process.env.DASH_VIEW_PASS || "", op = process.env.DASH_OPERATOR_PASS || "";
  const a = admin.length >= 8 && safeEq(given, admin);
  const o = op.length >= 8 && op !== admin && safeEq(given, op);
  const v = view.length >= 8 && view !== admin && view !== op && safeEq(given, view);
  return a ? "admin" : o ? "operator" : v ? "viewer" : null;
}

// ---- v13.4: two-factor sign-in (TOTP, RFC 6238) for admin and operator when DASH_TOTP_SECRET (base32, 16+ chars) is set
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32decode(str) {
  let bits = "", out = [];
  for (const ch of String(str).toUpperCase().replace(/[^A-Z2-7]/g, "")) bits += B32.indexOf(ch).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
export const totpRequired = (role) => role !== "viewer" && String(process.env.DASH_TOTP_SECRET || "").replace(/[^A-Za-z2-7]/g, "").length >= 16;
export function totpAt(secret, step) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac("sha1", b32decode(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String(((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, "0");
}
// accepts the current code and one step either side (clock drift); a code that was already used is refused (replay)
export function checkTotp(code, now = Date.now()) {
  code = String(code || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(code)) return false;
  const cur = Math.floor(now / 30000);
  for (const st of [cur, cur - 1, cur + 1]) {
    if (safeEq(code, totpAt(process.env.DASH_TOTP_SECRET, st))) {
      if (st <= (S.totpLast || 0)) return false;
      S.totpLast = st; return true;
    }
  }
  return false;
}

// ---- v13.11: backup codes for a lost phone. multi/make_backup_codes.py stores only SHA-256 hashes in DASH_BACKUP_CODES; each code works ONCE
//      (used hashes are kept in a small file, so the proxy and the route handlers agree), and it is as rate-limited as a password.
const USED = () => process.env.DASH_BACKUP_USED || path.join(process.cwd(), "..", "multi", "logs", "dashboard_backup_used.txt");
const normCode = (c) => String(c || "").toLowerCase().replace(/[^a-z2-7]/g, "");
export const backupHash = (c) => crypto.createHash("sha256").update("ds-backup|" + normCode(c)).digest("hex");
export function checkBackup(code) {
  const n = normCode(code);
  if (n.length < 12 || n.length > 16) return false;
  const list = String(process.env.DASH_BACKUP_CODES || "").split(",").map((x) => x.trim()).filter(Boolean);
  const h = backupHash(n);
  let hit = false;
  for (const x of list) if (x.length === h.length && crypto.timingSafeEqual(Buffer.from(x), Buffer.from(h))) hit = true;   // no early exit
  if (!hit) return false;
  let used = ""; try { used = fs.readFileSync(USED(), "utf8"); } catch {}
  if (used.split("\n").includes(h)) return false;                      // already used
  try { fs.mkdirSync(path.dirname(USED()), { recursive: true }); fs.appendFileSync(USED(), h + "\n", { mode: 0o600 }); } catch { return false; }
  return true;
}

// ---- v13.11: finer permissions per action. Default: viewer = read only, operator = Layer 2 actions + demo, admin = everything (governance, audit).
//      DASH_PATH_ROLES="/api/rollback=admin,/api/recovery=operator" sets the lowest role that may POST to a path (viewer < operator < admin).
const RANK = { viewer: 0, operator: 1, admin: 2 };
const ADMIN_ONLY_PATHS = ["/api/admin/chain", "/api/audit"];
export function pathAllowed(role, pathname, method = "POST") {
  if (method === "GET" || method === "HEAD") return true;
  let need = ADMIN_ONLY_PATHS.includes(pathname) ? "admin" : "operator";
  for (const pair of String(process.env.DASH_PATH_ROLES || "").split(",")) {
    const i = pair.indexOf("="); if (i < 1) continue;
    const k = pair.slice(0, i).trim(), v = pair.slice(i + 1).trim();
    if (k === pathname && v in RANK) need = v;
  }
  return (RANK[role] ?? -1) >= RANK[need];
}

// ---- v13.4: a password must not cross a network in clear text: sign-in is refused over plain HTTP unless the client is this machine
//      (or TLS=1: then the dashboard is only reachable through the TLS proxy, or DASH_ALLOW_HTTP=1 for a private lab)
export function plainHttpRefused(req) {
  if (process.env.TLS === "1" || process.env.DASH_ALLOW_HTTP === "1") return false;
  const host = String(req.headers.get("host") || "").replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  const proto = String(req.headers.get("x-forwarded-proto") || "").split(",")[0].trim();
  return !(host === "localhost" || host === "127.0.0.1" || host === "::1" || proto === "https");
}

export function issue(role, prev) {
  const now = Math.floor(Date.now() / 1000);
  const t = { r: role, i: now, e: now + IDLE_S, a: prev ? prev.a : now + MAX_S, s: prev ? prev.s : crypto.randomBytes(12).toString("hex") };
  t.e = Math.min(t.e, t.a);
  const body = b64(JSON.stringify(t));
  return { token: body + "." + mac(body), data: t, maxAge: t.e - now };
}

export function verify(token) {
  if (!token || typeof token !== "string" || token.length > 600) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const want = mac(body);
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  let t; try { t = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (!t || (t.r !== "admin" && t.r !== "operator" && t.r !== "viewer") || now > t.e || now > t.a || isRevoked(t.s)) return null;
  return t;
}
// revoked sessions live in a small file, because the proxy and the route handlers may run as separate module instances
const REV = () => process.env.DASH_REVOKED || path.join(process.cwd(), "..", "multi", "logs", "dashboard_revoked.txt");
let revCache = { m: -1, set: new Set() };
function isRevoked(sid) {
  if (S.revoked.has(sid)) return true;
  try {
    const m = fs.statSync(REV()).mtimeMs;
    if (m !== revCache.m) revCache = { m, set: new Set(fs.readFileSync(REV(), "utf8").split("\n").filter(Boolean)) };
    return revCache.set.has(sid);
  } catch { return false; }
}
export const revoke = (t) => {
  if (!t || !t.s) return;
  S.revoked.add(t.s);
  try { fs.mkdirSync(path.dirname(REV()), { recursive: true }); fs.appendFileSync(REV(), t.s + "\n", { mode: 0o600 }); } catch {}
};

export function cookieHeader(token, maxAge) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${SECURE ? "; Secure" : ""}`;
}
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${SECURE ? "; Secure" : ""}`;

export function readCookie(req) {
  const h = req.headers.get("cookie") || "";
  for (const part of h.split(";")) { const i = part.indexOf("="); if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim(); }
  return "";
}
export const sessionOf = (req) => verify(readCookie(req));

// the address of the client; X-Forwarded-For is trusted only when a reverse proxy in front is declared (DASH_TRUST_PROXY=1)
export function clientIp(req) {
  if (process.env.DASH_TRUST_PROXY === "1") {
    const x = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
    if (/^[0-9a-fA-F.:]{3,45}$/.test(x)) return x;
  }
  return "direct";
}

// ---- login lockout: 5 failures -> 30 s, doubling to 15 min; a global counter slows a distributed guesser too
function slot(k) { let f = S.fails.get(k); if (!f) { f = { n: 0, until: 0, last: 0 }; S.fails.set(k, f); } return f; }
export function lockedFor(ip) {
  const now = Date.now();
  return Math.max(0, ...["ip:" + ip, "global"].map((k) => Math.ceil(((S.fails.get(k) || { until: 0 }).until - now) / 1000)));
}
export function noteFail(ip) {
  const now = Date.now();
  for (const [k, lim] of [["ip:" + ip, 5], ["global", 20]]) {
    const f = slot(k);
    if (now - f.last > 3600e3) f.n = 0;
    f.n++; f.last = now;
    if (f.n >= lim) f.until = now + Math.min(900e3, 30e3 * 2 ** Math.min(10, f.n - lim));
  }
  if (S.fails.size > 2000) S.fails.clear();
}
export function noteOk(ip) { S.fails.delete("ip:" + ip); }

// ---- same-origin: a state-changing request must come from this dashboard's own pages
export function sameOrigin(req) {
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin") return false;
  const o = req.headers.get("origin");
  if (o) { try { return new URL(o).host === (req.headers.get("host") || ""); } catch { return false; } }
  return !!site || req.headers.get("x-ds-confirm") === "1";
}

// ---- audit log: every login, logout, refusal and admin action; each line carries the hash of the previous one
const AUDIT = () => process.env.DASH_AUDIT || path.join(process.cwd(), "..", "multi", "logs", "dashboard_audit.jsonl");
const hashLine = (o) => crypto.createHash("sha256").update(JSON.stringify(o)).digest("hex");
function lastHash() {
  if (S.auditPrev) return S.auditPrev;
  try {
    const lines = fs.readFileSync(AUDIT(), "utf8").trim().split("\n").filter(Boolean);
    S.auditPrev = lines.length ? JSON.parse(lines[lines.length - 1]).h : "0".repeat(64);
  } catch { S.auditPrev = "0".repeat(64); }
  return S.auditPrev;
}
export function audit(action, who, ip, detail) {
  try {
    const e = { t: new Date().toISOString(), who: who || "-", ip: ip || "-", action, detail: String(detail || "").slice(0, 300), prev: lastHash() };
    e.h = hashLine(e);
    fs.mkdirSync(path.dirname(AUDIT()), { recursive: true });
    fs.appendFileSync(AUDIT(), JSON.stringify(e) + "\n", { mode: 0o600 });
    S.auditPrev = e.h;
    mirror(JSON.stringify(e));
  } catch {}
}
// v13.4: a second copy of every audit line, so deleting the local file does not erase the history.
//   DASH_AUDIT_MIRROR=/path/on/another/disk-or-share.jsonl     and/or     DASH_AUDIT_WEBHOOK=https://collector/endpoint (POST, one JSON per line)
function mirror(line) {
  const f = process.env.DASH_AUDIT_MIRROR, u = process.env.DASH_AUDIT_WEBHOOK;
  if (f) { try { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.appendFileSync(f, line + "\n", { mode: 0o600 }); } catch {} }
  if (u && /^https?:\/\//.test(u)) { try { fetch(u, { method: "POST", headers: { "content-type": "application/json" }, body: line, signal: AbortSignal.timeout(3000) }).catch(() => {}); } catch {} }
}
export function readAudit(n = 100) {
  let lines = [];
  try { lines = fs.readFileSync(AUDIT(), "utf8").trim().split("\n").filter(Boolean); } catch {}
  let prev = "0".repeat(64), ok = true, bad = -1;
  const all = lines.map((l, i) => {
    let e = {}; try { e = JSON.parse(l); } catch { ok = false; bad = bad < 0 ? i : bad; return null; }
    const { h, ...rest } = e;
    if (rest.prev !== prev || hashLine(rest) !== h) { if (ok) bad = i; ok = false; }
    prev = h || prev;
    return e;
  }).filter(Boolean);
  return { ok, bad, total: all.length, entries: all.slice(-n).reverse() };
}

export function securityHeaders(h, nonce) {
  const dev = process.env.NODE_ENV !== "production";
  h.set("Content-Security-Policy", ["default-src 'self'", nonce ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}` : `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ""}`, ...(nonce && !dev ? [`style-src 'self' 'nonce-${nonce}'`, "style-src-attr 'unsafe-inline'"] : ["style-src 'self' 'unsafe-inline'"]),     // v13.5: <style> elements need the nonce; only style="" attributes (no code can run from them) stay open
    "img-src 'self' data:", "font-src 'self' data:", "connect-src 'self'" + (dev ? " ws: wss:" : ""), "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"].join("; "));
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  h.set("Cross-Origin-Resource-Policy", "same-origin");
  if (SECURE) h.set("Strict-Transport-Security", "max-age=31536000");
  return h;
}

// helpers for route handlers (the proxy has already checked the session; this is the second lock)
export function who(req) {
  const t = sessionOf(req);
  return { role: t ? t.r : null, ip: clientIp(req), name: t ? t.r : "-" };
}
export const needAdmin = (req) => needRole(req, ["admin"]);
export const needOperator = (req) => needRole(req, ["admin", "operator"]);   // Layer 2 actions and the demo
function needRole(req, roles) {
  const w = who(req);
  if (!roles.includes(w.role)) { audit("DENIED", w.name, w.ip, req.method + " " + new URL(req.url).pathname); return { w, deny: Response.json({ ok: false, error: "your role may not do this" }, { status: 403 }) }; }
  if (!sameOrigin(req) || req.headers.get("x-ds-confirm") !== "1") { audit("CSRF_REFUSED", w.name, w.ip, new URL(req.url).pathname); return { w, deny: Response.json({ ok: false, error: "cross-site or unconfirmed request refused" }, { status: 403 }) }; }
  return { w, deny: null };
}
export const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
export const IPV6 = /^[0-9a-fA-F:]{2,39}$/;
export const validIp = (s) => typeof s === "string" && (IPV4.test(s) ? s.split(".").every((x) => +x <= 255) : IPV6.test(s) && s.includes(":"));
export const validNode = (s) => typeof s === "string" && /^[A-Za-z0-9]{2,20}MSP:[A-Za-z0-9@._-]{1,90}$/.test(s);
