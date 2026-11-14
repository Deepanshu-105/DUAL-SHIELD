import fs from "fs";
import path from "path";
import http from "http";
import https from "https";

// Talks to the Fabric gateway on this laptop (fabric/gateway/server.js). who 0 = the dashboard's own identity (owner / governor).
const TLS = process.env.TLS === "1";
const GW = process.env.GATEWAY_URL || `${TLS ? "https" : "http"}://127.0.0.1:${process.env.GATEWAY_PORT || 8600}`;
const TLS_DIR = process.env.TLS_DIR || path.join(process.cwd(), "..", "multi", "tls", "dashboard");

export function call(method, p, obj, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const u = new URL(GW + p), body = obj ? JSON.stringify(obj) : null;
    const opt = { host: u.hostname, port: u.port, path: u.pathname + u.search, method, timeout,
      headers: body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {} };
    let mod = http;
    if (TLS) {
      mod = https;
      Object.assign(opt, { ca: fs.readFileSync(path.join(TLS_DIR, "ca.crt")), cert: fs.readFileSync(path.join(TLS_DIR, "node.crt")),
        key: fs.readFileSync(path.join(TLS_DIR, "node.key")), minVersion: "TLSv1.2", rejectUnauthorized: true, checkServerIdentity: () => undefined });
    }
    const r = mod.request(opt, (res) => {
      const ch = []; res.on("data", (c) => ch.push(c));
      res.on("end", () => { try { const o = JSON.parse(Buffer.concat(ch).toString()); o.ok === false ? reject(new Error(o.error)) : resolve(o); } catch (e) { reject(e); } });
    });
    r.on("error", reject); r.on("timeout", () => r.destroy(new Error("gateway timeout")));
    if (body) r.write(body);
    r.end();
  });
}
export const q = async (fn, ...args) => JSON.parse((await call("POST", "/query", { who: 0, fn, args })).result);
export const tx = async (fn, ...args) => { const r = await call("POST", "/tx", { who: 0, fn, args }, 30000); try { return JSON.parse(r.result); } catch { return r.result; } };
