"use client";
import { useEffect, useState } from "react";
import { JsonRpcProvider, Contract } from "ethers";

const RPC = "http://127.0.0.1:8545";
const NAMES = ["Node A (target)", "Node B (peer)", "Node C"];
const WARMUP = "203.0.113.1";   // start_lab.sh warm-up report: not a real attack
const real = (l) => (l ? l.filter((i) => i !== WARMUP) : null);

export default function ShieldLive() {
  const [s, setS] = useState({ status: "connecting..." });
  const [det, setDet] = useState({ flagged: 0, kills: 0 });
  const [blk, setBlk] = useState({});
  const [tl, setTl] = useState([]);
  const [rb, setRb] = useState(null);
  const [busy, setBusy] = useState(false);
  const [mx, setMx] = useState([]);
  const [live, setLive] = useState({ multi: false });

  useEffect(() => {
    let alive = true;
    let provider = null, contract = null, addrs = [];

    async function init() {
      const dep = await (await fetch("/localhost.json", { cache: "no-store" })).json();
      provider = new JsonRpcProvider(RPC);
      contract = new Contract(dep.address, dep.abi, provider);
      const accounts = await provider.send("eth_accounts", []);
      addrs = accounts.slice(1, 4); // accounts 1,2,3 are the registered nodes
    }

    async function tick() {
      try {
        if (!contract) await init();
        const k = Number(await contract.K());
        const n = Number(await contract.nodeCount());
        const events = (await contract.queryFilter(contract.filters.ThreatReported(), 0)).filter((e) => e.args.ip !== WARMUP);
        const ip = events.length ? events[events.length - 1].args.ip : null;
        const [count, , confirmed] = ip
          ? await contract.getTally(ip)
          : [0n, BigInt(k), false];
        const reporters = new Set(
          events.filter((e) => e.args.ip === ip).map((e) => e.args.node.toLowerCase())
        );
        const nodes = await Promise.all(
          addrs.map(async (a) => ({
            addr: a,
            stake: await contract.stakes(a),
            reported: reporters.has(a.toLowerCase()),
          }))
        );
        if (alive) setS({ status: "live", k, n, ip, count: Number(count), confirmed, nodes });
      } catch (e) {
        contract = null; // force a fresh init on the next tick
        if (alive) setS({ status: "error: " + (e.shortMessage || e.message) });
      }
    }

    tick();
    const id = setInterval(tick, 2000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    let alive = true;
    async function poll() {
      try {
        const r = await fetch("/api/detector", { cache: "no-store" });
        if (alive) setDet(await r.json());
      } catch {}
    }
    poll();
    const id = setInterval(poll, 1000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    let alive = true;
    async function poll() {
      try {
        const [b, l] = await Promise.all([
          fetch("/api/blocked", { cache: "no-store" }).then((r) => r.json()),
          fetch("/api/timeline", { cache: "no-store" }).then((r) => r.json()),
        ]);
        if (alive) { setBlk(b); setTl(l); }
      } catch {}
    }
    poll();
    const id = setInterval(poll, 2000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    fetch("/metrics.json", { cache: "no-store" }).then((r) => r.json()).then(setMx).catch(() => {});
  }, []);

  useEffect(() => {   // four-laptop mode: numbers for the run that just happened
    let alive = true;
    async function poll() {
      try {
        const r = await fetch("/api/live", { cache: "no-store" });
        if (alive) setLive(await r.json());
      } catch {}
    }
    poll();
    const id = setInterval(poll, 2000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const fmt = (v) => (v === null || v === undefined ? "waiting..." : v >= 1000 ? (v / 1000).toFixed(2) + " s" : v + " ms");
  const restoreMs = rb && rb.output ? (rb.output.match(/RESTORED \d+ files.*?([\d.]+) ms/) || [])[1] : null;
  const thisRun = !live.multi ? [] : [
    { label: "Local block on target", value: fmt(live.dropMs), note: "log line to ipset, laptop T" },
    { label: "Peer blocked after target", value: live.clockWarning ? "clocks differ" : fmt(live.peerMs), note: "T to P, clock-synced estimate" },
    { label: "Kill after trigger", value: fmt(live.killMs), note: "KILL_TRIGGER to process dead, laptop T" },
    { label: "First flag to kill", value: fmt(live.flagToKillMs), note: "laptop T" },
    { label: "Rollback restore", value: restoreMs ? restoreMs + " ms" : "click rollback", note: "files restored on T" },
    { label: "Rollback click, end to end", value: rb && rb.ms ? fmt(rb.ms) : "click rollback", note: "D to T over the network, includes the chain check" },
  ];

  async function doRollback() {
    setBusy(true);
    try {
      const r = await fetch("/api/rollback", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({}),   // the server picks the IP (ATTACKER_IP, default 172.30.0.12)
      });
      setRb(await r.json());
    } catch (e) { setRb({ ok: false, output: String(e) }); }
    setBusy(false);
  }

  if (s.status !== "live") {
    return <main style={{ padding: 24, fontFamily: "sans-serif" }}>Chain: {s.status}</main>;
  }

  const colour = (n) =>
    n.stake === 0n ? "#c62828"            // slashed
    : n.reported && s.confirmed ? "#1565c0" // took part in consensus
    : n.reported ? "#ef6c00"                // reported, waiting for a second report
    : "#2e7d32";                            // protected

  const label = (n) =>
    n.stake === 0n ? "slashed"
    : n.reported && s.confirmed ? "consensus"
    : n.reported ? "reported"
    : "protected";

  return (
    <main style={{ padding: 24, fontFamily: "sans-serif" }}>
      <h1>Dual-Shield</h1>
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div style={{ background: s.confirmed ? "#c62828" : "#2e7d32", color: "#fff", padding: "8px 14px", borderRadius: 20 }}>
          Layer 1 (network + chain): {s.confirmed ? "THREAT CONFIRMED" : "monitoring"}
        </div>
        <div style={{ background: det.kills ? "#c62828" : "#2e7d32", color: "#fff", padding: "8px 14px", borderRadius: 20 }}>
          Layer 2 (ransomware): {det.kills ? "ATTACK STOPPED (" + det.kills + " kill)" : "monitoring"}
        </div>
      </div>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        {s.nodes.map((n, i) => (
          <div key={n.addr} style={{ background: colour(n), color: "#fff", padding: 16, borderRadius: 8, minWidth: 200 }}>
            <strong>{NAMES[i]}</strong>
            <div>{label(n)}</div>
            <div style={{ fontSize: 12 }}>{n.addr.slice(0, 10)}...</div>
            <div style={{ fontSize: 12 }}>stake: {Number(n.stake) / 1e18} ETH</div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 16, marginTop: 24 }}>
        <div style={{ background: det.flagged ? "#ef6c00" : "#455a64", color: "#fff", padding: 16, borderRadius: 8, minWidth: 200 }}>
          <strong>Files flagged</strong>
          <div style={{ fontSize: 32 }}>{det.flagged}</div>
        </div>
        <div style={{ background: det.kills ? "#c62828" : "#455a64", color: "#fff", padding: 16, borderRadius: 8, minWidth: 200 }}>
          <strong>Kills triggered</strong>
          <div style={{ fontSize: 32 }}>{det.kills}</div>
        </div>
      </div>
      <h2 style={{ marginTop: 24 }}>
        Consensus tally: {s.count} of {s.n} reports ({s.k} needed)
        {s.confirmed ? "  CONFIRMED" : ""}
      </h2>
      <div>Latest reported IP: {s.ip ?? "none yet"}</div>
      <div style={{ display: "flex", gap: 16, marginTop: 24, flexWrap: "wrap" }}>
        {["target", "peer"].map((n) => (
          <div key={n} style={{ background: "#37474f", color: "#fff", padding: 16, borderRadius: 8, minWidth: 200 }}>
            <strong>Blocked on {n}</strong>
            <div style={{ fontSize: 32 }}>{real(blk[n]) ? real(blk[n]).length : "n/a"}</div>
            <div style={{ fontSize: 12 }}>{real(blk[n]) ? real(blk[n]).slice(0, 4).join(", ") : "container not running"}</div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 24 }}>
        <button onClick={doRollback} disabled={busy}
          style={{ padding: "10px 18px", borderRadius: 8, border: 0, background: "#1565c0", color: "#fff", fontSize: 16, cursor: "pointer" }}>
          {busy ? "Restoring..." : "Roll back to clean state"}
        </button>
        {rb && (
          <pre style={{ background: rb.ok ? "#e8f5e9" : "#ffebee", color: "#111", padding: 12, borderRadius: 8, marginTop: 12, whiteSpace: "pre-wrap" }}>
            {(rb.ok ? "ROLLED BACK" : "REFUSED / FAILED") + " (" + rb.ms + " ms)\n" + rb.output}
          </pre>
        )}
      </div>
      {live.multi && (
        <>
          <h2 style={{ marginTop: 24 }}>This run (four laptops){live.ip ? ", attacker " + live.ip : ""}</h2>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {thisRun.map((m) => (
              <div key={m.label} style={{ background: "#1b3a4b", color: "#fff", padding: 12, borderRadius: 8, minWidth: 170 }}>
                <div style={{ fontSize: 12, opacity: 0.8 }}>{m.label}</div>
                <div style={{ fontSize: 24 }}>{m.value}</div>
                <div style={{ fontSize: 11, opacity: 0.7 }}>{m.note}</div>
              </div>
            ))}
          </div>
        </>
      )}
      <h2 style={{ marginTop: 24 }}>{live.multi ? "Measured performance (lab, frozen)" : "Measured performance"}</h2>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {mx.map((m) => (
          <div key={m.label} style={{ background: "#263238", color: "#fff", padding: 12, borderRadius: 8, minWidth: 170 }}>
            <div style={{ fontSize: 12, opacity: 0.8 }}>{m.label}</div>
            <div style={{ fontSize: 24 }}>{m.value}</div>
            <div style={{ fontSize: 11, opacity: 0.7 }}>{m.note}</div>
          </div>
        ))}
      </div>
      <h2 style={{ marginTop: 24 }}>Event timeline</h2>
      <div style={{ fontFamily: "monospace", fontSize: 13 }}>
        {tl.length === 0 && <div>no events yet</div>}
        {tl.map((e, i) => (
          <div key={i} style={{ padding: "3px 0" }}>
            {new Date(e.ts * 1000).toLocaleTimeString()}  L{e.layer}  {e.text}
          </div>
        ))}
      </div>
    </main>
  );
}
