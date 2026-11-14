// Four-laptop mode. When MULTI=1 the dashboard (laptop D) asks small HTTP agents on the target (T)
// and peer (P) laptops instead of running `docker exec` on its own machine.
// v2: every request is signed with that laptop's own secret (HMAC-SHA256, time, nonce) and every answer
// must carry a valid signature back. The secret itself never crosses the network.
import crypto from "crypto";
import https from "https";

export const MULTI = process.env.MULTI === "1";
// v7: TLS=1 -> mutual TLS to the agents. Certificates from multi/make_tls.sh (TLS_DIR = multi/tls/dashboard).
// The agent's certificate must be signed by our private CA and carry the role name (hostnames are not used: discovery
// means addresses change), exactly as multi/tlsutil.py checks it.
const TLS = process.env.TLS === "1";
const SCHEME = TLS ? "https" : "http";
const TLS_DIR = process.env.TLS_DIR || path.join(process.cwd(), "..", "multi", "tls", "dashboard");
let _creds = null;
const creds = () => (_creds ||= { ca: fs.readFileSync(path.join(TLS_DIR, "ca.crt")), cert: fs.readFileSync(path.join(TLS_DIR, "node.crt")), key: fs.readFileSync(path.join(TLS_DIR, "node.key")) });
function tlsFetch(url, { method, headers, body, timeout }, expectCn) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      host: u.hostname.replace(/^\[|\]$/g, ""), port: u.port, path: u.pathname + u.search, method, headers, ...creds(), minVersion: "TLSv1.2",
      rejectUnauthorized: true, timeout,
      checkServerIdentity: (_host, cert) => (cert && cert.subject && cert.subject.CN === expectCn ? undefined : new Error("agent certificate is for " + (cert && cert.subject && cert.subject.CN) + ", expected " + expectCn)),
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
import fs from "fs";
import path from "path";
const URLS = { target: process.env.TARGET_AGENT, peer: process.env.PEER_AGENT };
// v6 discovery (DISCOVERY=1): T and P register with the registry on this laptop; follow their current address.
// A peer counts only while its heartbeat is fresh. Falls back to TARGET_AGENT / PEER_AGENT when nothing is registered.
export function discovered() {
  if (process.env.DISCOVERY !== "1") return null;
  try {
    const d = JSON.parse(fs.readFileSync(path.join(process.cwd(), "..", "multi", "peers.json"), "utf8"));
    const now = Date.now() / 1000, ttl = d.ttl || 120, out = {};
    for (const [role, p] of Object.entries(d.peers || {})) out[role] = { ...p, online: now - p.last <= ttl, age: Math.round(now - p.last) };
    return out;
  } catch { return null; }
}
function urlFor(who) {
  const d = discovered();
  if (d && d[who] && d[who].online && /^[0-9a-fA-F.:]+$/.test(d[who].ip)) return "http://" + (d[who].ip.includes(":") ? "[" + d[who].ip + "]" : d[who].ip) + ":8800";
  return URLS[who] && !URLS[who].includes("//:") ? URLS[who] : undefined;
}
const SECRETS = { target: process.env.AGENT_SECRET_T || "", peer: process.env.AGENT_SECRET_P || "" };
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const hmac = (secret, parts) => crypto.createHmac("sha256", secret).update(parts.join("\n")).digest("hex");

export async function agent(who, path, opts = {}) {
  const base = urlFor(who), secret = SECRETS[who];
  if (!base) throw new Error("no agent URL for " + who);
  if (secret.length < 16) throw new Error("AGENT_SECRET_" + (who === "target" ? "T" : "P") + " not set");
  const method = opts.method || "GET";
  const body = opts.body || "";
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(16).toString("hex");
  const sig = hmac(secret, [method, path, ts, nonce, sha(body)]);
  const headers = { "X-Ts": ts, "X-Nonce": nonce, "X-Sig": sig, "content-type": "application/json" };
  let r, text, got;
  if (TLS) {
    const t = await tlsFetch(base + path, { method, headers, body, timeout: opts.timeout || 3000 }, "dualshield-" + who);
    r = { status: t.status }; text = t.text; got = String(t.headers["x-resp-sig"] || "");
  } else {
    r = await fetch(base + path, { ...opts, method, cache: "no-store", signal: AbortSignal.timeout(opts.timeout || 3000), headers });
    text = await r.text(); got = r.headers.get("x-resp-sig") || "";
  }
  const want = hmac(secret, [nonce, String(r.status), sha(text)]);
  const ok = got.length === want.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want));
  if (!ok) throw new Error("agent " + who + " answer is not signed correctly (" + r.status + ")");
  return JSON.parse(text);
}

export async function agentLog(who, name, n = 60) {
  try { return (await agent(who, `/log?name=${name}&n=${n}`)).lines || []; } catch { return []; }
}
