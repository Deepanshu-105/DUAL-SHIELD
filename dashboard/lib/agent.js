// Four-laptop mode. When MULTI=1 the dashboard (laptop D) asks small HTTP agents on the target (T)
// and peer (P) laptops instead of running `docker exec` on its own machine.
export const MULTI = process.env.MULTI === "1";
const URLS = { target: process.env.TARGET_AGENT, peer: process.env.PEER_AGENT };
const TOKEN = process.env.AGENT_TOKEN || "dualshield";

export async function agent(who, path, opts = {}) {
  const base = URLS[who];
  if (!base) throw new Error("no agent URL for " + who);
  const r = await fetch(base + path, {
    ...opts, cache: "no-store", signal: AbortSignal.timeout(opts.timeout || 3000),
    headers: { "X-Token": TOKEN, "content-type": "application/json" },
  });
  return r.json();
}

export async function agentLog(who, name, n = 60) {
  try { return (await agent(who, `/log?name=${name}&n=${n}`)).lines || []; } catch { return []; }
}
