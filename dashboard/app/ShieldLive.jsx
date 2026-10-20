"use client";
import { useEffect, useState } from "react";
import { JsonRpcProvider, Contract } from "ethers";

const RPC = "http://127.0.0.1:8545";
const NAMES = ["Node A (target)", "Node B (peer)", "Node C"];

export default function ShieldLive() {
  const [s, setS] = useState({ status: "connecting..." });

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
        const events = await contract.queryFilter(contract.filters.ThreatReported(), 0);
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
      <h1>Dual-Shield: Layer 1</h1>
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
      <h2 style={{ marginTop: 24 }}>
        Consensus tally: {s.count} of {s.n} reports ({s.k} needed)
        {s.confirmed ? "  CONFIRMED" : ""}
      </h2>
      <div>Latest reported IP: {s.ip ?? "none yet"}</div>
    </main>
  );
}
