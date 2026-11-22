// v13.21: turns the guard logs of T and P into dashboard events. Pure functions (tested by test_events.mjs).
// Sources (read through the signed agent): web (web_guard), host (host_guard), nodewatch, keeper (blockkeeper).
const SEV = { CRITICAL: "bad", HIGH: "bad", MEDIUM: "warn", INFO: "info" };

export function parseTime(prefix, now = new Date()) {
  // "2026-11-21 17:40:05" (full) or "17:40:05" (time only: today)
  let m = prefix.match(/^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime() / 1000;
  m = prefix.match(/^(\d\d):(\d\d):(\d\d)/);
  if (m) {
    const d = new Date(now); d.setHours(+m[1], +m[2], +m[3], 0);
    if (d.getTime() > now.getTime() + 3600e3) d.setDate(d.getDate() - 1);   // a log line from just before midnight
    return d.getTime() / 1000;
  }
  return null;
}

// -> {ts, node, kind, title, detail, sev, actions[]} or null (a line that is not an event)
export function parseLine(line, node, source, now = new Date()) {
  const m = line.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d|\d\d:\d\d:\d\d) (.*)$/);
  if (!m) return null;
  const ts = parseTime(m[1], now), rest = m[2];
  const ev = (kind, title, detail, sev, actions) => ({ ts, node, kind, title, detail, sev, actions: actions || [], source });
  let x;
  if ((x = rest.match(/^WEB_ATTACK (\S+) (?:web attack: (.+)|http-flood (.+)|linked to the file change.*)$/))) {
    const why = x[2] || (x[3] ? "HTTP flood" : "web shell / defacement source");
    return ev("web", "Web attack: " + why, "from " + x[1], "bad", ["reported to chain", "blocked " + x[1]]);
  }
  if ((x = rest.match(/^WEB_SKIP (\S+) not blocked \((.+)\)$/))) return ev("web", "Web attack not blocked", x[1] + " (" + x[2] + ")", "info", []);
  if ((x = rest.match(/^WEB_RESTORED (\S+)/))) return ev("web", "Defaced / deleted file restored", x[1], "ok", ["restored from clean snapshot"]);
  if ((x = rest.match(/^WEB_QUARANTINED (\S+)/))) return ev("web", "Web shell quarantined", x[1], "bad", ["moved out of the web root (mode 000)"]);
  if ((x = rest.match(/^HOST_ATTACK (\S+) pid=(\d+) (.+?) \| (.*?) \| (.*)$/))) {
    const acts = x[5].split("; ").filter(Boolean);
    return ev("host", "Host attack: " + x[3], "pid " + x[2] + " · " + x[4], x[1] === "HIGH" ? "bad" : "warn", acts);
  }
  if ((x = rest.match(/^HOST_ALERT pid=(\d+) (.+?) \| (.*)$/))) return ev("host", "Suspicious program: " + x[2], "pid " + x[1] + " · " + x[3], "warn", []);
  if ((x = rest.match(/^NODEWATCH_ALERT (CRITICAL|HIGH|MEDIUM|INFO) (.*)$/))) return ev("node", "Host change: " + x[2], "", SEV[x[1]] || "warn", []);
  if ((x = rest.match(/^BLOCKKEEPER_TAMPER (.*)$/))) return ev("keeper", "Firewall tampering undone", x[1], "bad", ["block restored"]);
  return null;
}

export function summarize(events) {
  const c = { web: 0, host: 0, node: 0, keeper: 0, restored: 0, quarantined: 0, killed: 0, blocked: 0 };
  for (const e of events) {
    if (e.kind in c && e.sev !== "info") c[e.kind]++;
    for (const a of e.actions) {
      if (/restored from/.test(a)) c.restored++;
      if (/quarantin|mode 000/.test(a)) c.quarantined++;
      if (/^killed/.test(a)) c.killed++;
      if (/^blocked/.test(a)) c.blocked++;
    }
  }
  return c;
}
