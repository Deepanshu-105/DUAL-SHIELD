"use client";
import { useCallback, useEffect, useState } from "react";

const TABS = [["overview", "Overview"], ["l1", "Layer 1 · Network"], ["chain", "Consensus & Chain"], ["gov", "Governance"], ["l2", "Layer 2 · Ransomware"], ["sec", "Security posture"], ["audit", "Audit log"]];
const TYPES = { crypto: "Encrypting ransomware", wiper: "Wiper (destroys data)", double_extortion: "Double extortion", exfiltration: "Data theft", note_only: "Ransom note only" };
const WARM = "203.0.113.1";

function usePoll(url, ms, enabled = true) {
  const [d, setD] = useState(null);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const go = async () => {
      try {
        const r = await fetch(url, { cache: "no-store" });
        if (r.status === 401) { window.location.href = "/login"; return; }
        const j = await r.json(); if (alive) setD(j);
      } catch {}
    };
    go(); const id = setInterval(go, ms);
    return () => { alive = false; clearInterval(id); };
  }, [url, ms, enabled]);
  return d;
}
const age = (s) => (s == null ? "n/a" : s < 90 ? Math.round(s) + " s ago" : Math.round(s / 60) + " min ago");
const fmt = (v) => (v == null ? "waiting…" : v >= 1000 ? (v / 1000).toFixed(2) + " s" : v + " ms");
const hhmm = (ts) => new Date(ts * 1000).toLocaleTimeString();

const Tile = ({ label, value, note, tone }) => (
  <div className={"card tile " + (tone || "")}><h3>{label}</h3><div className="big">{value}</div>{note && <div className="note">{note}</div>}</div>
);
const Explain = ({ title, children }) => (<div className="explain"><b>{title}</b><br />{children}</div>);

export default function AdminConsole() {
  const [tab, setTab] = useState("overview");
  const [toast, setToast] = useState(null);
  const [busy, setBusy] = useState("");
  const me = usePoll("/api/auth/me", 15000);
  const admin = me && me.role === "admin";
  const chain = usePoll("/api/chain", 2000);
  const det = usePoll("/api/detector", 1500);
  const blk = usePoll("/api/blocked", 2000);
  const tl = usePoll("/api/timeline", 2000);
  const live = usePoll("/api/live", 2000);
  const rec = usePoll("/api/recovery", 2500);
  const peers = usePoll("/api/peers", 5000);
  const adm = usePoll("/api/admin/chain", 3000, tab === "chain" || tab === "gov");
  const aud = usePoll("/api/audit", 4000, tab === "audit" && admin);
  const [rbOut, setRbOut] = useState(null);

  useEffect(() => { if (toast) { const id = setTimeout(() => setToast(null), 9000); return () => clearTimeout(id); } }, [toast]);

  const post = useCallback(async (url, body, ask, tag) => {
    if (ask && !window.confirm(ask)) return null;
    setBusy(tag || url);
    try {
      const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-ds-confirm": "1" }, body: JSON.stringify(body || {}) });
      if (r.status === 401) { window.location.href = "/login"; return null; }
      const j = await r.json(); setBusy(""); return j;
    } catch (e) { setBusy(""); return { ok: false, error: String(e) }; }
  }, []);
  const logout = async () => { await post("/api/auth/logout", {}); window.location.href = "/login"; };

  const confirmed = chain && chain.confirmed, killed = det && det.kills > 0;
  const nodeTone = (n) => (n.slashed ? "#b91c1c" : n.stake === 0 ? "#475569" : n.reported && confirmed ? "#0369a1" : n.reported ? "#b45309" : "#15803d");
  const nodeLabel = (n) => (n.slashed ? "slashed (stake lost)" : n.stake === 0 ? "not registered yet" : n.reported && confirmed ? "took part in consensus" : n.reported ? "reported" : "protected");
  const timeline = Array.isArray(tl) ? tl : [];
  const tNode = blk && blk.target, pNode = blk && blk.peer;
  const l2 = !rec || !rec.available ? [] : [
    { label: "Vault", value: rec.frozen ? "FROZEN" : "protecting", note: rec.frozen ? (rec.freeze && rec.freeze.reason) || "attack suspected" : rec.commits + " snapshots", tone: rec.frozen ? "bad" : "ok" },
    { label: "Last snapshot", value: rec.last_commit ? age(rec.last_commit.age_s) : "none", note: rec.last_commit ? "rev " + rec.last_commit.rev : "" },
    { label: "Guard", value: rec.guard_alive ? "running" : "stopped", note: rec.guard ? "kill " + (rec.guard.kill ? "on" : "off") + ", held files " + rec.guard.held : "", tone: rec.guard_alive ? "ok" : "bad" },
    { label: "Containment", value: rec.containment ? String(rec.containment.mode).toUpperCase() : "idle", note: rec.containment ? rec.containment.reason : "no attack seen", tone: rec.containment ? "warn" : "" },
    { label: "Attack type", value: rec.classification && rec.classification.primary ? TYPES[rec.classification.primary] || rec.classification.primary : "none seen" },
    { label: "Self-protection", value: rec.selfguard ? (rec.selfguard.ok ? "OK" : "ALERT") : "not running", tone: rec.selfguard && !rec.selfguard.ok ? "bad" : "" },
    { label: "Last recovery", value: rec.recovery ? (rec.recovery.ok ? "OK" : "FAILED") : "none yet", note: rec.recovery && rec.recovery.ok ? rec.recovery.files + " files, " + rec.recovery.ms + " ms" : "", tone: rec.recovery ? (rec.recovery.ok ? "ok" : "bad") : "" },
  ];

  async function runRansomware() { const j = await post("/api/admin/demo", { action: "ransomware" }, "Start the MOCK ransomware on the target (it only touches the sample folder)?", "demo"); if (j) setToast(j.output || j.error || JSON.stringify(j)); }
  async function rollback() { const j = await post("/api/rollback", {}, "Restore the protected folder from the clean snapshot? The chain check runs first.", "rb"); if (j) { setRbOut(j); setToast(j.ok ? "Rollback OK" : "Rollback: " + (j.output || j.error)); } }
  async function recovery(a) { const j = await post("/api/recovery", { action: a }, a === "recover" ? "Recover from the newest verified vault snapshot? The encrypted folder is kept as evidence." : "Unfreeze the vault and restart the guard? Only after recovery, on a clean machine.", a); if (j) { setRbOut(j); setToast((j.ok ? "OK: " : "Failed: ") + (j.output || j.error || "")); } }
  const [form, setForm] = useState({ kind: "2", ip: "", node: "", value: "" });
  async function propose(e) { e.preventDefault(); const j = await post("/api/admin/chain", { action: "propose", ...form }, "Submit this proposal to the chain?", "prop"); if (j) setToast(j.ok ? "Proposal submitted: " + JSON.stringify(j.result) : "Refused: " + j.error); }
  async function approve(id) { const j = await post("/api/admin/chain", { action: "approve", id }, "Sign proposal " + id + " as governor?", "ap" + id); if (j) setToast(j.ok ? "Signed proposal " + id : "Refused: " + j.error); }

  const Timeline = ({ layer }) => (
    <div className="list">{timeline.filter((x) => !layer || x.layer === layer).slice(0, 12).map((x, i) => (
      <div className="row" key={i}><span className="t">{hhmm(x.ts)}</span><span className={"pill " + (x.layer === 1 ? "info" : "warn")}>L{x.layer}</span><span>{x.text}</span></div>))}
      {!timeline.length && <div className="note">No events yet.</div>}</div>
  );
  const Chips = ({ list }) => list === null || list === undefined ? <span className="note">not reachable</span> : (list.filter((i) => i !== WARM).length ? list.filter((i) => i !== WARM).map((ip) => <span className="pill bad mono" style={{ margin: 2 }} key={ip}>{ip}</span>) : <span className="note">empty</span>);

  return (
    <div className="shell">
      <nav className="side" aria-label="Sections">
        <h2>🛡 Dual-Shield</h2>
        {TABS.filter(([k]) => k !== "audit" || admin).map(([k, l]) => <button key={k} className={"tab" + (tab === k ? " on" : "")} onClick={() => setTab(k)}>{l}</button>)}
        <div className="spacer" />
        <div className="who">Signed in as <b>{me ? me.role : "…"}</b>{me && <><br />session ends in {Math.ceil(me.expiresIn / 60)} min of inactivity</>}</div>
        <button className="tab" onClick={logout}>Sign out</button>
      </nav>
      <main className="main">
        <div className="head">
          <h1>{TABS.find(([k]) => k === tab)[1]}</h1>
          <span className={"pill " + (chain && chain.status === "live" ? "ok" : "bad")}>{chain && chain.status === "live" ? "Fabric chain live" : "chain: " + (chain ? chain.status : "connecting…")}</span>
          <span className={"pill " + (confirmed ? "bad" : "ok")}>Layer 1: {confirmed ? "THREAT CONFIRMED" : "monitoring"}</span>
          <span className={"pill " + (killed ? "bad" : "ok")}>Layer 2: {killed ? "ATTACK STOPPED" : "monitoring"}</span>
          {!admin && me && <span className="pill mut">read-only</span>}
        </div>

        {tab === "overview" && <>
          <Explain title="What you are looking at">Layer 1 stops network attacks (SSH guessing, floods, scans, spoofing) on the target, and shares each confirmed attacker through a Hyperledger Fabric chain so the peer blocks it too once <b>K nodes agree</b>. Layer 2 stops ransomware on the machine, kills the process, and restores the files from a verified vault. Use the tabs to see and operate each part.</Explain>
          <div className="grid">
            <Tile label="Consensus needed (K)" value={chain && chain.k != null ? chain.k : "…"} note={chain ? chain.n + " staked nodes" : ""} />
            <Tile label="Latest attacker" value={chain && chain.ip ? chain.ip : "none"} note={chain && chain.ip ? chain.count + " of " + chain.k + " reports" : "waiting for an attack"} tone={confirmed ? "bad" : ""} />
            <Tile label="Blocked on target" value={tNode ? tNode.filter((i) => i !== WARM).length : "n/a"} note="Layer 1 firewall set" />
            <Tile label="Blocked on peer" value={pNode ? pNode.filter((i) => i !== WARM).length : "n/a"} note="learned from the chain" />
            <Tile label="Files flagged / kills" value={det ? det.flagged + " / " + det.kills : "…"} note="Layer 2 kill rule" tone={killed ? "bad" : ""} />
            <Tile label="Vault" value={rec && rec.available ? (rec.frozen ? "FROZEN" : "protecting") : "n/a"} note={rec && rec.available ? rec.commits + " snapshots" : ""} tone={rec && rec.frozen ? "bad" : "ok"} />
          </div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>NODES</h3>
          <div className="grid">{chain && chain.nodes && chain.nodes.map((n, i) => (
            <div className="node" style={{ background: nodeTone(n) }} key={n.addr}><b>{["Node A (target, Org1)", "Node B (peer, Org2)", "Node C (Org1)"][i]}</b><div>{nodeLabel(n)}</div><div className="mono">stake {n.stake} · {n.addr.split("@")[0]}</div></div>))}</div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>LATEST EVENTS</h3><Timeline />
        </>}

        {tab === "l1" && <>
          <Explain title="Layer 1 · what is implemented">SSH parser (failed logins → block in ms) · slow brute force / password spraying / stolen-credential login · SYN, UDP and connection floods, port scans · ARP spoofing · sensor-data spoofing · Tor and bad-HASSH fingerprints · IPv4 + IPv6 · Linux (ipset/iptables) and Windows (firewall rules). <b>Try it:</b> run the attacker menu on laptop A and watch the lists and timeline below fill in.</Explain>
          <div className="grid">
            <Tile label="Local block on target" value={live && live.multi ? fmt(live.dropMs) : "n/a"} note="log line → firewall, laptop T" />
            <Tile label="Peer blocked after target" value={live && live.multi ? (live.clockWarning ? "clocks differ" : fmt(live.peerMs)) : "n/a"} note="T → chain → P" />
            <Tile label="Flood / scan blocks" value={live && live.multi ? live.floods : "n/a"} note={live && live.lastFlood ? live.lastFlood.kind + " from " + live.lastFlood.ip : "enable FLOOD=1"} />
            <Tile label="Slow-login / ARP / sensor alerts" value={live && live.others ? live.others.login + " / " + live.others.arp + " / " + live.others.sensor : "n/a"} note="login_watch, arp_watch, sensor_guard" />
          </div>
          <div className="grid two" style={{ marginTop: 12 }}>
            <div className="card"><h3>Blocked on target (T)</h3><Chips list={tNode} /></div>
            <div className="card"><h3>Blocked on peer (P)</h3><Chips list={pNode} /></div>
          </div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>LAYER 1 TIMELINE</h3><Timeline layer={1} />
        </>}

        {tab === "chain" && <>
          <Explain title="Why a blockchain here">One laptop saying "this IP is an attacker" can be wrong or hacked. The chain only turns a report into a <b>confirmed threat after K different staked nodes report it</b>. A node that reported something later overruled loses its stake (slashing). Fabric makes this a permissioned ledger: no coins, no gas.</Explain>
          <div className="grid">
            <Tile label="K (reports needed)" value={adm && adm.params ? adm.params.required : "…"} note={adm && adm.params ? "stake per node " + adm.params.STAKE + ", window " + adm.params.WINDOW + " s" : ""} />
            <Tile label="Staked nodes" value={adm && adm.params ? adm.params.nodeCount : "…"} />
            <Tile label="Slashed pool" value={adm && adm.params ? adm.params.slashedPool : "…"} note="stake forfeited by bad reporters" />
          </div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>THREAT TALLIES</h3>
          <div className="list">{adm && adm.tallies && adm.tallies.length ? adm.tallies.map((t) => <div className="row" key={t.ip}><span className="mono">{t.ip}</span><span>{t.count}/{t.k} reports</span><span className={"pill " + (t.confirmed ? "bad" : "warn")}>{t.confirmed ? "CONFIRMED" : "pending"}</span>{t.active === false && t.confirmed && <span className="pill mut">overruled</span>}</div>) : <div className="note">No reports yet.</div>}</div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>NODES</h3>
          <div className="list">{adm && adm.nodes && adm.nodes.map((n) => <div className="row" key={n.addr}><span className="mono">{n.addr}</span><span className={"pill " + (n.stake > 0 ? "ok" : "bad")}>{n.stake > 0 ? "staked " + n.stake : n.approved ? "not registered" : "not approved"}</span>{n.governor && <span className="pill info">governor</span>}</div>)}</div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>LEDGER EVENTS (newest first)</h3>
          <div className="list">{adm && adm.events && adm.events.slice(0, 15).map((e, i) => <div className="row mono" key={i}>{e.name} {e.ip ? e.ip : ""} {e.node ? e.node.split("@")[0] : ""} {e.count != null ? "(" + e.count + ")" : ""}</div>)}</div>
        </>}

        {tab === "gov" && <>
          <Explain title="Governance (administrator)">Rules of the network are changed by <b>proposals</b>, not by editing files: protect an IP so it can never be blocked, overrule a wrong threat (slashes the nodes that reported it), approve or revoke a node, change K-related parameters. A proposal runs when enough governors sign. Every action here is audited.</Explain>
          <div className="card"><h3>New proposal</h3>
            <form className="form" onSubmit={propose}>
              <label>What<select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>{adm && adm.kinds && Object.entries(adm.kinds).map(([k, v]) => <option key={k} value={k}>{k} · {v}</option>)}</select></label>
              {["1", "2", "3"].includes(form.kind) && <label>IP address<input value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} placeholder="203.0.113.50" maxLength={45} /></label>}
              {["4", "5", "6", "7"].includes(form.kind) && <label>Node id<input value={form.node} onChange={(e) => setForm({ ...form, node: e.target.value })} placeholder="Org1MSP:User1@org1.example.com" maxLength={100} /></label>}
              {["8", "9", "10"].includes(form.kind) && <label>Value<input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} inputMode="numeric" maxLength={4} /></label>}
              <button className="btn" disabled={!admin || busy === "prop"}>Submit proposal</button>
            </form></div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>PROPOSALS</h3>
          <div className="list">{adm && adm.proposals && adm.proposals.length ? adm.proposals.map((p) => <div className="row" key={p.id}><b>#{p.id}</b><span>{(adm.kinds || {})[p.kind] || p.kind}</span><span className="mono">{p.ip || p.node || (p.value ? "value " + p.value : "")}</span><span className={"pill " + (p.executed ? "ok" : "warn")}>{p.executed ? "executed" : p.approvals + " signature(s)"}</span>{!p.executed && <button className="btn ghost" disabled={!admin || busy === "ap" + p.id} onClick={() => approve(p.id)}>Sign</button>}</div>) : <div className="note">No proposals yet.</div>}</div>
          {adm && adm.params && <div className="card" style={{ marginTop: 12 }}><h3>Current rules</h3><div className="mono">governors {adm.params.govCount} · signatures needed {adm.params.govThreshold} · quorum {adm.params.quorumPct}% · max reports/hour {adm.params.maxReportsPerHour || "unlimited"}</div></div>}
        </>}

        {tab === "l2" && <>
          <Explain title="Layer 2 · what is implemented">Early-warning canary files and write-rate watch → kill rule finds the process (kernel report on Linux, open files, top writer) and stops it → containment cuts the network (dry or apply) → attack classified (encrypt / wipe / double extortion / data theft / note only) → append-only encrypted vault restores a <b>verified</b> copy (checked against a manifest and the chain anchor). <b>Try it:</b> start the mock ransomware, then recover.</Explain>
          <div className="grid">{l2.length ? l2.map((t) => <Tile key={t.label} {...t} />) : <div className="note">Layer 2 data not available (guard not running or agent not reachable).</div>}</div>
          <div className="card" style={{ marginTop: 12 }}><h3>Operator actions {admin ? "" : "(administrator only)"}</h3>
            <div className="form">
              <button className="btn danger" disabled={!admin || !!busy} onClick={runRansomware}>▶ Start mock ransomware (demo)</button>
              <button className="btn" disabled={!admin || !!busy} onClick={rollback}>Roll back to clean state</button>
              <button className="btn" disabled={!admin || !!busy} onClick={() => recovery("recover")}>Recover from vault</button>
              <button className="btn ghost" disabled={!admin || !!busy} onClick={() => recovery("unfreeze")}>Unfreeze vault</button>
            </div>
            {rbOut && <pre className="mono note" style={{ whiteSpace: "pre-wrap" }}>{(rbOut.output || rbOut.error || "").slice(0, 900)}</pre>}
          </div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>LAYER 2 TIMELINE</h3><Timeline layer={2} />
        </>}

        {tab === "sec" && <>
          <Explain title="How this console protects itself">Sign-in with lockout · short sessions (idle logout, absolute limit) · HttpOnly + SameSite=Strict cookie · read-only and administrator roles · every change needs a same-origin request with a confirmation header · strict browser security headers (no framing, no foreign scripts, no cross-site requests) · agents answer only signed requests (HMAC, optional mutual TLS) · every action in a hash-chained audit log.</Explain>
          <div className="grid">
            <Tile label="Your role" value={me ? me.role : "…"} note={admin ? "can operate" : "read-only"} />
            <Tile label="Session" value={me ? Math.ceil(me.expiresIn / 60) + " min" : "…"} note={me ? "idle limit; hard limit " + Math.ceil(me.maxIn / 60) + " min" : ""} />
            <Tile label="Connection" value={typeof window !== "undefined" && window.location.protocol === "https:" ? "HTTPS" : "plain HTTP"} note={typeof window !== "undefined" && window.location.protocol === "https:" ? "encrypted" : "use TLS=1 / a TLS proxy outside the lab"} tone={typeof window !== "undefined" && window.location.protocol === "https:" ? "ok" : "warn"} />
            <Tile label="Self-protection (T)" value={rec && rec.selfguard ? (rec.selfguard.ok ? "OK" : "ALERT") : "not running"} note="signed file manifest, process watch" tone={rec && rec.selfguard && !rec.selfguard.ok ? "bad" : ""} />
          </div>
          <h3 className="muted" style={{ margin: "16px 0 8px" }}>REGISTERED LAPTOPS</h3>
          <div className="list">{peers && peers.peers && Object.keys(peers.peers).length ? Object.entries(peers.peers).map(([r, p]) => <div className="row" key={r}><b>{r}</b><span className="mono">{p.ip}</span><span className={"pill " + (p.online ? "ok" : "bad")}>{p.online ? "online" : "OFFLINE"}</span><span className="note">heartbeat {age(p.age)}</span></div>) : <div className="note">Discovery mode off, or no laptop registered.</div>}</div>
        </>}

        {tab === "audit" && admin && <>
          <Explain title="Audit log">Sign-ins, failures, lockouts, refused requests, rollbacks, recoveries, governance and demo actions. Each line contains the hash of the line before; if anyone edits or deletes one, the check below turns red.</Explain>
          <div className="head"><span className={"pill " + (aud && aud.ok ? "ok" : "bad")}>{aud ? (aud.ok ? "chain intact · " + aud.total + " entries" : "TAMPERED near entry " + aud.bad) : "loading…"}</span></div>
          <div className="list">{aud && aud.entries && aud.entries.map((e, i) => <div className="row" key={i}><span className="t mono">{e.t.slice(11, 19)}</span><span className={"pill " + (/FAIL|DENIED|REFUSED|LOCKED|ERROR/.test(e.action) ? "bad" : "info")}>{e.action}</span><span>{e.who}</span><span className="mono note">{e.ip}</span><span className="note">{e.detail}</span></div>)}</div>
        </>}
      </main>
      {toast && <div className="toast" role="status" onClick={() => setToast(null)}>{String(toast).slice(0, 600)}</div>}
    </div>
  );
}
