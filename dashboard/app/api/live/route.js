import { MULTI, agentLog } from "../../../lib/agent.js";

// Four-laptop mode only: numbers for the run that just happened, computed from the logs on T and P.
const HIDE = (ip) => ip === "203.0.113.1" || ip.startsWith("198.51.100.");   // warm-up and benchmark addresses
const grab = (lines, re) => lines.map((l) => l.match(re)).filter(Boolean);

export async function GET() {
  if (!MULTI) return Response.json({ multi: false });
  const [pb, eb, watch, met] = await Promise.all([
    agentLog("target", "parser_block", 50),
    agentLog("peer", "peer_block", 50),
    agentLog("target", "watch", 300),
    agentLog("target", "metrics", 100),
  ]);

  // Layer 1: T blocks, then P blocks. Two different laptops, so this relies on their clocks agreeing.
  const tBlocks = grab(pb, /PARSER_BLOCK ip=(\S+) ts=([\d.]+)/).map((m) => ({ ip: m[1], ts: +m[2] })).filter((x) => !HIDE(x.ip));
  const pBlocks = grab(eb, /PEER_BLOCK ip=(\S+) ts=([\d.]+)/).map((m) => ({ ip: m[1], ts: +m[2] }));
  const t = tBlocks[tBlocks.length - 1];
  let peerMs = null, clockWarning = false;
  if (t) {
    const p = pBlocks.filter((x) => x.ip === t.ip).pop();
    if (p) {
      const ms = Math.round((p.ts - t.ts) * 1000);
      if (ms < 0 || ms > 120000) clockWarning = true;   // negative or absurd: the laptops' clocks differ
      else peerMs = ms;
    }
  }
  const drops = grab(met, /METRIC drop_ms=([\d.]+)/);
  const dropMs = drops.length ? +(+drops[drops.length - 1][1]).toFixed(1) : null;

  // Layer 2: all on laptop T, so no clock problem.
  const flags = grab(watch, /^([\d.]+)\s+FLAGGED/);
  const trig = grab(watch, /^([\d.]+)\s+KILL_TRIGGER/).pop();
  const killed = grab(watch, /^([\d.]+)\s+KILLED pid=/).pop();
  const killMs = trig && killed ? +((+killed[1] - +trig[1]) * 1000).toFixed(2) : null;
  const flagToKillMs = flags.length && killed ? Math.round((+killed[1] - +flags[0][1]) * 1000) : null;

  return Response.json({ multi: true, ip: t ? t.ip : null, dropMs, peerMs, clockWarning, killMs, flagToKillMs });
}
