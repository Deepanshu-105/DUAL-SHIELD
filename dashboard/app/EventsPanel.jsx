"use client";
import { useEffect, useState } from "react";

const hhmm = (ts) => new Date(ts * 1000).toLocaleTimeString();
const KINDS = [["all", "All"], ["web", "Web attacks"], ["host", "Host attacks"], ["node", "Host changes"], ["keeper", "Firewall tampering"]];

export default function EventsPanel() {
  const [d, setD] = useState(null);
  const [kind, setKind] = useState("all");
  useEffect(() => {
    let alive = true;
    const go = async () => {
      try {
        const r = await fetch("/api/events", { cache: "no-store" });
        if (r.status === 401) { window.location.href = "/login"; return; }
        const j = await r.json(); if (alive) setD(j);
      } catch {}
    };
    go(); const id = setInterval(go, 2000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  const c = d && d.counts;
  const list = ((d && d.events) || []).filter((e) => kind === "all" || e.kind === kind);
  const T = ({ label, value, tone, note }) => (<div className={"card tile " + (tone || "")}><h3>{label}</h3><div className="big">{value}</div>{note && <div className="note">{note}</div>}</div>);
  return (<>
    <div className="explain"><b>Attack events</b><br />What the web guard, host guard, node watch and block keeper on T and P did: detected, blocked, killed, restored (retrieved) or quarantined. Network attacks (SSH, flood, scan) are on the Layer 1 tab, ransomware on the Layer 2 tab.</div>
    <div style={{ marginTop: 10 }}><a className="btn" style={{ textDecoration: "none", display: "inline-block" }} href="/api/report" target="_blank" rel="noreferrer">Incident report (print / PDF)</a></div>
    <div className="grid" style={{ marginTop: 12 }}>
      <T label="Web attacks" value={c ? c.web : "n/a"} tone={c && c.web ? "bad" : ""} note="SQLi, XSS, traversal, scanners, flood" />
      <T label="Host attacks" value={c ? c.host : "n/a"} tone={c && c.host ? "bad" : ""} note="reverse shells, miners" />
      <T label="Killed / blocked" value={c ? c.killed + " / " + c.blocked : "n/a"} note="processes / addresses" />
      <T label="Restored / quarantined" value={c ? c.restored + " / " + c.quarantined : "n/a"} tone={c && (c.restored || c.quarantined) ? "ok" : ""} note="files retrieved / shells and malware isolated" />
      <T label="Host changes" value={c ? c.node : "n/a"} tone={c && c.node ? "warn" : ""} note="new port, account, key, cron, module" />
      <T label="Firewall tampering" value={c ? c.keeper : "n/a"} tone={c && c.keeper ? "bad" : ""} note="blocks removed behind our back" />
    </div>
    <div style={{ margin: "14px 0 8px", display: "flex", gap: 6, flexWrap: "wrap" }}>
      {KINDS.map(([k, l]) => <button key={k} className={"btn" + (kind === k ? "" : " ghost")} style={{ marginRight: 6, marginTop: 10 }} onClick={() => setKind(k)}>{l}</button>)}
    </div>
    <div className="list">
      {list.map((e, i) => (
        <div className="row" key={i}>
          <span className="t">{hhmm(e.ts)}</span>
          <span className={"pill " + (e.sev === "bad" ? "bad" : e.sev === "ok" ? "ok" : e.sev === "warn" ? "warn" : "info")}>{e.node}</span>
          <span><b>{e.title}</b>{e.detail ? <span className="mono"> · {e.detail}</span> : null}</span>
          {e.actions.map((a, j) => <span key={j} className="pill mut">{a}</span>)}
        </div>))}
      {d && !list.length && <div className="note">No events yet. They appear when web_guard / host_guard / node_watch run on T and P and something happens.</div>}
      {!d && <div className="note">loading…</div>}
    </div>
  </>);
}
