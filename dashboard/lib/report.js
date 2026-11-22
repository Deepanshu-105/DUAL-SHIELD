// v13.22: printable incident report (plain HTML, no scripts). Pure function, tested by test_report.mjs.
// Every piece of log text is escaped: a log line can contain attacker-controlled bytes (a URL, a command line).
export const esc = (s) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const when = (ts) => { const d = new Date(ts * 1000); const p = (n) => String(n).padStart(2, "0"); return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()); };

export function renderReport(events, counts, meta = {}) {
  const c = counts || {};
  const rows = events.slice().sort((a, b) => a.ts - b.ts).map((e) =>
    "<tr><td>" + esc(when(e.ts)) + "</td><td>" + esc(e.node) + "</td><td>" + esc(e.sev === "bad" ? "HIGH" : e.sev === "warn" ? "MEDIUM" : e.sev === "ok" ? "RECOVERED" : "INFO") + "</td><td><b>" + esc(e.title) + "</b>" + (e.detail ? "<br>" + esc(e.detail) : "") + "</td><td>" + esc((e.actions || []).join("; ")) + "</td></tr>").join("\n");
  const n = (v) => esc(v == null ? 0 : v);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>DualShield incident report</title>
<style>body{font:14px/1.45 Arial,sans-serif;margin:28px;color:#111}h1{margin:0 0 4px}h2{margin:22px 0 6px;font-size:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:4px 7px;text-align:left;vertical-align:top;font-size:12.5px}th{background:#eee}.k{display:inline-block;margin:0 14px 6px 0}.note{color:#444;font-size:12px}@media print{.noprint{display:none}body{margin:10mm}}</style></head><body>
<p class="noprint"><button onclick="window.print()">Print / save as PDF</button></p>
<h1>DualShield incident report</h1>
<div class="note">Generated ${esc(meta.generated || "")} · for ${esc(meta.who || "authorised administrator")} · covers the last events still in the guard logs of T and P (not a full history)</div>
<h2>Summary</h2>
<div><span class="k">Web attacks: <b>${n(c.web)}</b></span><span class="k">Host attacks: <b>${n(c.host)}</b></span><span class="k">Host changes: <b>${n(c.node)}</b></span><span class="k">Firewall tampering: <b>${n(c.keeper)}</b></span></div>
<div><span class="k">Processes killed: <b>${n(c.killed)}</b></span><span class="k">Addresses blocked: <b>${n(c.blocked)}</b></span><span class="k">Files restored: <b>${n(c.restored)}</b></span><span class="k">Items quarantined: <b>${n(c.quarantined)}</b></span></div>
<h2>Timeline (oldest first)</h2>
${rows ? "<table><tr><th>Time</th><th>Node</th><th>Level</th><th>What happened</th><th>What DualShield did</th></tr>\n" + rows + "\n</table>" : "<p>No attack events in the logs.</p>"}
<h2>Limits of this report</h2>
<p class="note">Built from the guard logs on T and P. If a guard was not running, or an attacker with root deleted the logs, events are missing. Ransomware and network (SSH, flood, scan) incidents are on the Layer 2 and Layer 1 tabs of the dashboard. Signature-based detection: new attack styles can pass until a rule is added.</p>
</body></html>`;
}
